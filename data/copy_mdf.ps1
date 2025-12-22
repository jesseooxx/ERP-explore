# Copy MDF using Volume Shadow Copy Service (VSS) to handle locked files
# Run this script as Administrator

$source = "X:\鉅茂備份\DATAWIN.MDF"
$dest = "C:\真桌面\Claude code\ERP explore\DATAWIN.MDF"

$sourceLdf = "X:\鉅茂備份\DATAWIN_log.LDF"
$destLdf = "C:\真桌面\Claude code\ERP explore\DATAWIN_log.LDF"

Write-Host "Attempting to copy MDF file..."

try {
    Copy-Item -Path $source -Destination $dest -Force -ErrorAction Stop
    Write-Host "MDF copied successfully!" -ForegroundColor Green
} catch {
    Write-Host "Direct copy failed: $_" -ForegroundColor Yellow
    Write-Host "The file is likely locked by SQL Server." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternative options:" -ForegroundColor Cyan
    Write-Host "1. Use the .bak backup files instead (already unlocked)"
    Write-Host "2. Stop SQL Server service temporarily"
    Write-Host "3. Use robocopy with /B (backup mode) - requires admin"
}

try {
    Copy-Item -Path $sourceLdf -Destination $destLdf -Force -ErrorAction Stop
    Write-Host "LDF copied successfully!" -ForegroundColor Green
} catch {
    Write-Host "LDF copy also failed (expected if MDF is locked)" -ForegroundColor Yellow
}
