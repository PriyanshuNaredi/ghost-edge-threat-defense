@echo off
rem Full verification suite against a running Ghost gateway (default :8090).
setlocal
set GW=%1
if "%GW%"=="" set GW=http://127.0.0.1:8090

echo === 1. Clean traffic (expect upstream echo 200) ===
curl -s -H "X-Forwarded-For: 10.0.1.50" "%GW%/api/products"
echo.

echo === 2. SQLi (expect 403 BLOCK) ===
curl -s -H "X-Forwarded-For: 203.0.113.7" "%GW%/api/login?user=admin%%27%%20OR%%201%%3D1--&pass=x"
echo.

echo === 3. XSS (expect 403 BLOCK) ===
curl -s -H "X-Forwarded-For: 198.51.100.9" "%GW%/api/comments?body=%%3Cscript%%3Ealert(document.cookie)%%3C/script%%3E"
echo.

echo === 4. Path traversal (expect 403 BLOCK) ===
curl -s -H "X-Forwarded-For: 192.0.2.44" --path-as-is "%GW%/static/../../../../etc/passwd"
echo.

echo === 5. Rate limit flood (expect 200... 429... 403) ===
for /L %%i in (1,1,20) do curl -s -o NUL -w "%%{http_code} " -H "X-Forwarded-For: 172.16.99.99" "%GW%/api/feed"
echo.

echo === 6. Post-blacklist (expect 403 BLACKLIST) ===
curl -s -H "X-Forwarded-For: 172.16.99.99" "%GW%/api/feed"
echo.

echo === 7. Stats ===
curl -s "%GW%/ghost/stats"
echo.
