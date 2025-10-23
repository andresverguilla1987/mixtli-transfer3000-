Param(
  [string]$API = "https://mixtli-transfer3000.onrender.com/api",
  [string]$Folder = "$env:USERPROFILE\Uploads",
  [string[]]$Patterns = @("*.jpg","*.jpeg","*.png","*.gif","*.pdf","*.zip"),
  [int]$ExpireSec = 24*60*60
)
$OutCsv = Join-Path $env:TEMP ("mixtli-upload-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
function Get-ContentType([string]$path){
  switch([IO.Path]::GetExtension($path).ToLower()){
    ".jpg"{"image/jpeg"}".jpeg"{"image/jpeg"}".png"{"image/png"}
    ".gif"{"image/gif"}".webp"{"image/webp"}".pdf"{"application/pdf"}
    ".zip"{"application/zip"}".txt"{"text/plain"} default{"application/octet-stream"}
  }
}
if(-not (Test-Path -LiteralPath $Folder)){ New-Item -ItemType Directory -Force -Path $Folder | Out-Null }
$files=@(); foreach($pat in $Patterns){ $files+=Get-ChildItem -LiteralPath $Folder -File -Recurse -Include $pat -ErrorAction SilentlyContinue }
if($files.Count -eq 0){
  1..3|%{ $b=New-Object byte[](1024*$_*10); (New-Object Random).NextBytes($b); [IO.File]::WriteAllBytes((Join-Path $Folder ("test$_.jpg")),$b) }
  foreach($pat in $Patterns){ $files+=Get-ChildItem -LiteralPath $Folder -File -Recurse -Include $pat -ErrorAction SilentlyContinue }
}
$payloadFiles = $files | % { [pscustomobject]@{ name=$_.Name; size=$_.Length; type=(Get-ContentType $_.FullName) } }
$body = @{ files=$payloadFiles; expiresSeconds=[int]$ExpireSec } | ConvertTo-Json
try{ $pres=Invoke-RestMethod -Method Post -Uri "$API/presign" -ContentType "application/json" -Body $body }
catch{ Write-Error "Fallo /api/presign: $($_.Exception.Message)"; exit 1 }
if(-not $pres.ok){ Write-Error "Backend respondió error en presign:"; $pres|ConvertTo-Json -Depth 5|Write-Host; exit 1 }
$results=@()
for($i=0;$i -lt $files.Count;$i++){
  $f=$files[$i]; $p=$pres.results[$i]; if(-not $p.putUrl){ Write-Warning "Sin putUrl para $($f.Name)"; continue }
  $ctype=Get-ContentType $f.FullName
  Write-Host ("[{0}/{1}] {2} -> {3} bytes" -f ($i+1),$files.Count,$f.Name,$f.Length) -ForegroundColor Yellow
  $ok=$true; $status=""; $err=$null
  try{
    $args=@("-sS","-D","-","-o","NUL","-X","PUT","$($p.putUrl)","-H","Content-Type: $ctype","--upload-file","`"$($f.FullName)`"")
    $proc=Start-Process -FilePath "curl.exe" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\curl-headers.txt"
    $proc.WaitForExit()
    $hdr=Get-Content "$env:TEMP\curl-headers.txt"
    $status=($hdr|Select-String -Pattern "^HTTP/.*").Line
    if($proc.ExitCode -ne 0 -or ($hdr -notmatch "HTTP/.* 20(0|4)")){ $ok=$false; $err=($hdr -join "`n") }
  }catch{ $ok=$false; $err=$_.Exception.Message }
  if($ok){ Write-Host "   OK $status" -ForegroundColor Cyan } else { Write-Warning "   Error subiendo $($f.Name)"; if($err){ Write-Host ($err.Substring(0,[Math]::Min($err.Length,600))) -ForegroundColor DarkYellow } }
  $results += [pscustomobject]@{ FilePath=$f.FullName; FileName=$f.Name; Size=$f.Length; ContentType=$ctype; PutOK=$ok; PutStatus=$status; GetURL=$p.getUrl; ObjectURL=$p.objectUrl; Key=$p.key }
}
$results | Export-Csv -NoTypeInformation -Encoding UTF8 $OutCsv
$okc=($results|?{$_.PutOK}).Count; $bad=$results.Count-$okc
Write-Host "`nResumen: $okc OK, $bad con error. CSV: $OutCsv" -ForegroundColor Cyan
$results | ?{ $_.PutOK -and $_.GetURL } | Select FileName,GetURL | ft -AutoSize
