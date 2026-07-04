[CmdletBinding()]
param(
    [string[]] $Arguments = @("--version"),
    [string] $Image = "infra-ansible-tools:local",
    [switch] $Build
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Dockerfile = Join-Path $RepoRoot "tools\ansible\Dockerfile"

function Invoke-Docker {
    param([string[]] $DockerArguments)

    if (Get-Command rtk -ErrorAction SilentlyContinue) {
        & rtk docker @DockerArguments
        return
    }

    & docker @DockerArguments
}

if ($Build) {
    Invoke-Docker -DockerArguments @("build", "-t", $Image, "-f", $Dockerfile, $RepoRoot)
}

$mount = "${RepoRoot}:/work"
# docker run equivalent, preferring rtk docker when available.
Invoke-Docker -DockerArguments (@(
        "run",
        "--rm",
        "-e",
        "ANSIBLE_CONFIG=/work/ansible.cfg",
        "-v",
        $mount,
        "-w",
        "/work",
        $Image
    ) + $Arguments)
