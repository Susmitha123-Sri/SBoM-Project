# PowerShell script to view scan reports easily
# Usage: .\view_reports.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SBOM Scan Reports Viewer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$reportsPath = "C:\New folder\reports"

# Check if reports directory exists
if (-Not (Test-Path $reportsPath)) {
    Write-Host "Error: Reports directory not found at: $reportsPath" -ForegroundColor Red
    Write-Host "Please run a scan first to generate reports." -ForegroundColor Yellow
    exit
}

# List all reports
Write-Host "Available Scan Reports:" -ForegroundColor Green
Write-Host ""

$jsonFiles = Get-ChildItem -Path $reportsPath -Filter "*.json" | Sort-Object LastWriteTime -Descending

if ($jsonFiles.Count -eq 0) {
    Write-Host "No reports found. Run a scan first!" -ForegroundColor Yellow
    exit
}

# Display report list
for ($i = 0; $i -lt $jsonFiles.Count; $i++) {
    $file = $jsonFiles[$i]
    $scanId = $file.BaseName
    $date = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "$($i + 1). $scanId" -ForegroundColor White
    Write-Host "   Modified: $date" -ForegroundColor Gray
    
    # Try to read and show summary from JSON
    try {
        $jsonContent = Get-Content $file.FullName | ConvertFrom-Json
        $summary = $jsonContent.summary
        if ($summary) {
            Write-Host "   Packages: $($summary.total_packages) | Vulnerabilities: $($summary.total_vulnerabilities)" -ForegroundColor Gray
        }
    } catch {
        # Ignore if can't parse
    }
    Write-Host ""
}

Write-Host "Options:" -ForegroundColor Cyan
Write-Host "1. Open reports folder in Windows Explorer"
Write-Host "2. View a specific report (enter number)"
Write-Host "3. Open all reports folder"
Write-Host "4. Exit"
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host "Opening reports folder..." -ForegroundColor Green
        explorer $reportsPath
    }
    "2" {
        $reportNum = Read-Host "Enter report number (1-$($jsonFiles.Count))"
        try {
            $reportIndex = [int]$reportNum - 1
            if ($reportIndex -ge 0 -and $reportIndex -lt $jsonFiles.Count) {
                $selectedFile = $jsonFiles[$reportIndex]
                Write-Host "Opening: $($selectedFile.Name)" -ForegroundColor Green
                Start-Process $selectedFile.FullName
                
                # Also open CSV if exists
                $csvFile = Join-Path $reportsPath "$($selectedFile.BaseName).csv"
                if (Test-Path $csvFile) {
                    Start-Process $csvFile
                }
            } else {
                Write-Host "Invalid report number!" -ForegroundColor Red
            }
        } catch {
            Write-Host "Invalid input!" -ForegroundColor Red
        }
    }
    "3" {
        Write-Host "Opening reports folder..." -ForegroundColor Green
        explorer $reportsPath
    }
    "4" {
        Write-Host "Goodbye!" -ForegroundColor Cyan
    }
    default {
        Write-Host "Invalid choice!" -ForegroundColor Red
    }
}

