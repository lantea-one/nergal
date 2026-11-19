"""Stage only the test build and required framework runtime for mapped identities, never private home data."""
from pathlib import Path
import os
import shutil


def stage_client_runtime(root, assembly):
    source = Path(shutil.which('dotnet')).resolve().parent
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o755)
    shutil.copy2(source / 'dotnet', runtime / 'dotnet')
    shutil.copytree(source / 'host' / 'fxr', runtime / 'host' / 'fxr')
    shutil.copytree(source / 'shared' / 'Microsoft.NETCore.App', runtime / 'shared' / 'Microsoft.NETCore.App')
    application = root / 'application'
    shutil.copytree(Path(assembly).parent, application)
    # The host's private home/toolchain parent permissions remain unchanged. Only
    # these disposable synthetic build/runtime copies are readable by mapped UIDs.
    for tree in (runtime, application):
        for directory, _, files in os.walk(tree):
            os.chmod(directory, 0o755)
            for name in files:
                os.chmod(Path(directory) / name, 0o644)
    os.chmod(runtime / 'dotnet', 0o755)
    return str(runtime / 'dotnet'), str(application / Path(assembly).name)
