import tempfile
import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException, UploadFile

from app.api import resources
from app.models.database import ResourceType
from app.schemas import ManualPVCCreateRequest, TokenPayload


class PvcApiFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_create_manual_pvc_resource_success(self):
        request = ManualPVCCreateRequest(
            name='e2e-manual-pvc',
            description='manual pvc for test',
            project_id='p1',
            pvc_size=3,
            resource_type='other',
        )
        user = TokenPayload(id=1, username='admin', role=['ordinary_admin'])

        db = mock.MagicMock()
        project_record = SimpleNamespace(id='p1')

        def query_side_effect(model):
            query = mock.MagicMock()
            query.filter.return_value.first.return_value = project_record
            return query

        db.query.side_effect = query_side_effect
        db.refresh.side_effect = lambda resource: setattr(resource, 'id', 123)

        fake_k8s = mock.MagicMock()
        fake_k8s.storage_class_name = 'nfs-storage-192.168.13.66'
        fake_k8s.get_pvc_name.return_value = 'secflow-pvc-test'
        fake_k8s.get_project_namespace.return_value = 'secflow-p1'
        fake_k8s.create_pvc.return_value = True

        with (
            mock.patch('app.api.resources.validate_project_access', new=mock.AsyncMock(return_value=(True, {'id': 'p1'}))),
            mock.patch('app.api.resources.get_k8s_service', return_value=fake_k8s),
            mock.patch('app.api.resources.get_config', return_value={'k8s': {'storage_class_name': 'nfs-storage-192.168.13.66'}}),
        ):
            response = await resources.create_manual_pvc_resource(request, (user, 'token'), db)

        self.assertEqual(response.resource_id, 123)
        self.assertEqual(response.pvc_name, 'secflow-pvc-test')
        self.assertEqual(response.namespace, 'secflow-p1')
        self.assertEqual(response.capacity, '3Gi')

    async def test_create_manual_pvc_resource_permission_denied(self):
        request = ManualPVCCreateRequest(
            name='forbidden',
            description='forbidden',
            project_id='p-forbidden',
            pvc_size=3,
            resource_type='other',
        )
        user = TokenPayload(id=1, username='admin', role=['ordinary_admin'])

        with mock.patch('app.api.resources.validate_project_access', new=mock.AsyncMock(return_value=(False, None))):
            with self.assertRaises(HTTPException) as context:
                await resources.create_manual_pvc_resource(request, (user, 'token'), mock.MagicMock())

        self.assertEqual(context.exception.status_code, 403)

    async def test_upload_resource_creates_task(self):
        user = TokenPayload(id=1, username='admin', role=['ordinary_admin'])
        db = mock.MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            upload = UploadFile(filename='sample.tar.gz', file=BytesIO(b'dummy-archive-content'))
            with (
                mock.patch('app.api.resources.validate_project_access', new=mock.AsyncMock(return_value=(True, {'id': 'p1'}))),
                mock.patch('app.api.resources.create_upload_extract_task', new=mock.AsyncMock(return_value='task-123')),
                mock.patch('app.api.resources.get_config', return_value={'app': {'download_base_url': 'http://resource.test', 'upload_dir': tmpdir}}),
            ):
                response = await resources.upload_resource(
                    file=upload,
                    name='archive-resource',
                    resource_type=ResourceType.CODE,
                    project_ids='p1',
                    pvc_size=2,
                    user_and_token=(user, 'token'),
                    db=db,
                )

            self.assertEqual(response.task_id, 'task-123')
            self.assertTrue(response.resource_uuid)

    async def test_upload_resource_rejects_empty_project_ids(self):
        user = TokenPayload(id=1, username='admin', role=['ordinary_admin'])
        upload = UploadFile(filename='a.zip', file=BytesIO(b'abc'))

        with self.assertRaises(HTTPException) as context:
            await resources.upload_resource(
                file=upload,
                name='archive-resource',
                resource_type=ResourceType.OTHER,
                project_ids=' , ',
                pvc_size=2,
                user_and_token=(user, 'token'),
                db=mock.MagicMock(),
            )

        self.assertEqual(context.exception.status_code, 400)

    async def test_get_resource_pvc_detail_fields(self):
        resource = SimpleNamespace(
            id=88,
            resource_uuid='uuid-88',
            name='manual-resource',
            description='desc',
            resource_type='other',
            pvc_name='secflow-pvc-88',
            pvc_namespace='secflow-p1',
            pvc_size='5Gi',
            upload_status='completed',
            projects=[SimpleNamespace(id='p1')],
            created_at='2026-04-02T00:00:00Z',
            updated_at='2026-04-02T00:00:00Z',
        )

        fake_k8s = mock.MagicMock()
        fake_k8s.get_pvc_status.return_value = {'status': 'Bound', 'storage_class': 'nfs-storage-192.168.13.66'}
        fake_k8s.check_pvc_in_use.return_value = (False, '')

        with (
            mock.patch('app.api.resources._load_pvc_resource_with_access', new=mock.AsyncMock(return_value=(resource, 'p1', 'token'))),
            mock.patch('app.api.resources.get_k8s_service', return_value=fake_k8s),
        ):
            payload = await resources.get_resource_pvc_detail(88, (TokenPayload(id=1), 'token'), mock.MagicMock())

        self.assertEqual(payload['id'], 88)
        self.assertEqual(payload['pvc_name'], 'secflow-pvc-88')
        self.assertIn('pvc_k8s_status', payload)
        self.assertIn('in_use', payload)

    async def test_browser_endpoints_cover_success_and_error_paths(self):
        resource = SimpleNamespace(pvc_name='secflow-pvc-99')
        fake_browser = mock.MagicMock()
        fake_browser.create_directory.return_value = {'message': 'Directory created', 'path': '/docs'}
        fake_browser.delete_node.side_effect = HTTPException(status_code=400, detail='Root path cannot be deleted')
        fake_browser.upload_file = mock.AsyncMock(side_effect=HTTPException(status_code=404, detail='Target directory not found'))

        with (
            mock.patch('app.api.resources._load_pvc_resource_with_access', new=mock.AsyncMock(return_value=(resource, 'p1', 'token'))),
            mock.patch('app.api.resources.get_pvc_browser_service', return_value=fake_browser),
        ):
            create_result = await resources.create_resource_pvc_browser_directory(
                99,
                resources.OutputPVCBrowserCreateDirectoryRequest(path='/', name='docs'),
                (TokenPayload(id=1), 'token'),
                mock.MagicMock(),
            )
            self.assertEqual(create_result['path'], '/docs')

            with self.assertRaises(HTTPException) as delete_context:
                await resources.delete_resource_pvc_browser_node(
                    99,
                    path='/',
                    user_and_token=(TokenPayload(id=1), 'token'),
                    db=mock.MagicMock(),
                )
            self.assertEqual(delete_context.exception.status_code, 400)

            with self.assertRaises(HTTPException) as upload_context:
                await resources.upload_resource_pvc_browser_file(
                    99,
                    path='/not-exists',
                    file=UploadFile(filename='a.txt', file=BytesIO(b'a')),
                    user_and_token=(TokenPayload(id=1), 'token'),
                    db=mock.MagicMock(),
                )
            self.assertEqual(upload_context.exception.status_code, 404)


if __name__ == '__main__':
    unittest.main()
