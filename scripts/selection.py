from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class SelectionOption:
    value: str
    display_name: str
    description: str = ""
    aliases: tuple[str, ...] = ()


def split_target_tokens(targets: Iterable[str]) -> list[str]:
    selected: list[str] = []
    for target in targets:
        parts = [part.strip() for part in target.split(",")]
        selected.extend(part for part in parts if part)
    return selected


def prompt_for_named_targets(
    *,
    item_label: str,
    options: Sequence[SelectionOption],
    example: str,
    no_selection_message: str,
) -> list[str]:
    print(f"Select {item_label}. Enter 0 for all, or choose by number or name. Examples: {example}")
    name_width = max((len(option.display_name) for option in options), default=10)
    print(f"{0:>2}. {'all':<{name_width}} all services")
    for index, option in enumerate(options, start=1):
        line = f"{index:>2}. {option.display_name:<{name_width}}"
        if option.description:
            line += f" {option.description}"
        print(line)

    response = input("Selection: ").strip()
    if not response:
        raise SystemExit(no_selection_message)
    return split_target_tokens(response.replace(" ", ",").split(","))


def resolve_named_targets(
    targets: Iterable[str],
    *,
    options: Sequence[SelectionOption],
    item_label: str,
    example: str,
    unknown_label: str,
    no_selection_message: str,
) -> list[str]:
    selected_targets = split_target_tokens(targets)
    if not selected_targets:
        selected_targets = prompt_for_named_targets(
            item_label=item_label,
            options=options,
            example=example,
            no_selection_message=no_selection_message,
        )

    if {"0", "all"} & {target.lower() for target in selected_targets}:
        return [option.value for option in options]

    option_index: dict[str, str] = {}
    for index, option in enumerate(options, start=1):
        option_index[str(index)] = option.value
        option_index[option.value] = option.value
        option_index[option.value.lower()] = option.value
        option_index[option.display_name] = option.value
        option_index[option.display_name.lower()] = option.value
        for alias in option.aliases:
            option_index[alias] = option.value
            option_index[alias.lower()] = option.value

    resolved: list[str] = []
    seen: set[str] = set()
    for target in selected_targets:
        value = option_index.get(target) or option_index.get(target.lower())
        if value is None:
            available = ", ".join(option.display_name for option in options)
            raise SystemExit(f"Unknown {unknown_label}: {target}\nAvailable: {available}")
        if value not in seen:
            resolved.append(value)
            seen.add(value)
    return resolved
