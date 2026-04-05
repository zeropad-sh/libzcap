param(
    [string]$BuildDir = "examples/build",
    [string]$Summary = "bench_results/incoming/windows-x86_64/summary.txt",
    [string]$Sample = "tests/sample.pcap"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $Summary)) {
    New-Item -ItemType File -Path $Summary -Force | Out-Null
}

function Invoke-RequiredExample {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string]$Expected,
        [string[]]$Arguments = @(),
        [int[]]$AllowedExitCodes = @(0)
    )

    "Running required example: $Label" | Tee-Object -FilePath $Summary -Append
    $exePath = Join-Path $BuildDir $Executable
    $output = & $exePath @Arguments 2>&1
    $rc = $LASTEXITCODE
    $output | Tee-Object -FilePath $Summary -Append

    if ($AllowedExitCodes -notcontains $rc) {
        throw "FAIL: $Label exited with $rc"
    }

    if ($rc -ne 0) {
        "PASS: $Label exited with expected code $rc" | Tee-Object -FilePath $Summary -Append
        return
    }

    if ($Expected -and -not ($output -match [regex]::Escape($Expected))) {
        throw "FAIL: $Label missing expected output '$Expected'"
    }
}

Invoke-RequiredExample -Label "03_offline_read_cpp" -Executable "03_offline_read_cpp.exe" -Expected "Done reading buffer trace." -Arguments @($Sample)
Invoke-RequiredExample -Label "07_offline_split_ipv4_cpp" -Executable "07_offline_split_ipv4_cpp.exe" -Expected "Saved output to ipv4_only.pcap" -Arguments @($Sample)
Invoke-RequiredExample -Label "09_offline_split_transport_cpp" -Executable "09_offline_split_transport_cpp.exe" -Expected "written:" -Arguments @($Sample)
Invoke-RequiredExample -Label "08_offline_protocol_stats_c" -Executable "08_offline_protocol_stats_c.exe" -Expected "packets processed:" -Arguments @($Sample)
Invoke-RequiredExample -Label "11_findalldevs_lookupdev_c" -Executable "11_findalldevs_lookupdev_c.exe" -Expected "findalldevs failed: UnsupportedPlatform" -AllowedExitCodes @(0, 1)
Invoke-RequiredExample -Label "12_nonblocking_stats_c" -Executable "12_nonblocking_stats_c.exe" -Expected "zpcap_stats:" -Arguments @($Sample)
Invoke-RequiredExample -Label "15_findalldevs_lookupdev_cpp" -Executable "15_findalldevs_lookupdev_cpp.exe" -Expected "findalldevs failed: UnsupportedPlatform" -AllowedExitCodes @(0, 1)
Invoke-RequiredExample -Label "16_nonblocking_stats_cpp" -Executable "16_nonblocking_stats_cpp.exe" -Expected "zpcap_stats:" -Arguments @($Sample)
Invoke-RequiredExample -Label "19_async_native_wait_cpp" -Executable "19_async_native_wait_cpp.exe" -Expected "Loop finished after" -Arguments @("--offline", $Sample, "18")
