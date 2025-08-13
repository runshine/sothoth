package com.guance.javaagent;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class JavaAgentLoader {
    static final Logger logger = LoggerFactory.getLogger(JavaAgentLoader.class);


    public static void loadAgent(Config config) {
        logger.info("dynamically loading javaagent");
        logger.info("config.options:"+ config.getOptions());
        logger.info("config.agentSo: "+config.getAgentSo());
        logger.info("config.agentJar: "+config.getAgentJar());
        logger.info("config.pid: "+config.getPid());
        logger.info("config.displayName: "+config.getDisplayName());
        boolean idMode = false;
        boolean nameMode= false;
        if (config.getPid() != null && !config.getPid().equals("")){
            idMode = true;
        }
        if (config.getDisplayName()!= null && !config.getDisplayName().equals("")){
            nameMode =true;
        }
        if (!idMode && !nameMode){
            logger.warn("-pid or -displayName must have a non empty");
            return;
        }
        try {
            List<VirtualMachineDescriptor> list = VirtualMachine.list();
            if(list.size()==0){
                logger.warn("Not found any java VirtualMachine");
            }
            for (int i = 0; i < list.size(); i++) {
                VirtualMachineDescriptor virtualMachineDescriptor = list.get(i);
                String pid = virtualMachineDescriptor.id();
// 		        logger.info(pid);
// 		        logger.info(virtualMachineDescriptor.displayName());
                VirtualMachine attach = null;
                if (idMode && config.getPid().equals(pid) ){
                     logger.info("Find a match VirtualMachine, pid: " + pid + ", name: " + virtualMachineDescriptor.displayName());
                     attach = VirtualMachine.attach(pid);
                }
                if (nameMode && virtualMachineDescriptor.displayName().equals(config.getDisplayName())){
                    logger.info("Find a match VirtualMachine, pid: " + pid + ", name: " + virtualMachineDescriptor.displayName());
                    attach = VirtualMachine.attach(pid);
                }
                if (attach == null){
                    logger.info("Not match VirtualMachine, pid: " + pid + ", name: " + virtualMachineDescriptor.displayName());
                    continue;
                }
                if (config.getAgentJar() != null && !config.getAgentJar().equals("")){
                    logger.info("try to loading java agent: " +config.getAgentJar() +  ", options: " + config.getOptions());
                    attach.loadAgent(config.getAgentJar(), config.getOptions());
                }
                 if (config.getAgentSo() != null && !config.getAgentSo().equals("")){
                    if( config.getOptions() == null ||  config.getOptions().length() == 0 ){
                        logger.info("try to loading native agent: " +config.getAgentSo() + " without options");
                        attach.loadAgentPath(config.getAgentSo());
                       }
                    else{
                        logger.info("try to loading native agent: " +config.getAgentSo() + ", options: " + config.getOptions() );
                        attach.loadAgentPath(config.getAgentSo(), config.getOptions());
                    }
                 }
                attach.detach();
                logger.info(String.format("attach agent success into [%s]",virtualMachineDescriptor.displayName()));
                System.exit(0);
                return;
            }
        } catch (Exception e) {
            logger.info(String.format("attach agent failed [%s]",e.toString()));
            throw new RuntimeException(e);
        }
        System.exit(255);
    }
}
