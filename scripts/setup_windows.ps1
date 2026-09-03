$ErrorActionPreference = "Stop"

Write-Host "[+] Installation des bibliotheques Python"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host ""
Write-Host "[+] Verification cible"
python .\main.py identify

Write-Host ""
Write-Host "[i] Interfaces : python .\main.py interfaces"
Write-Host "[i] Baseline   : python .\main.py baseline"
Write-Host "[i] Capture    : python .\main.py capture --seconds 90"
Write-Host ""
Write-Host "[!] La capture raw Windows necessite PowerShell/PyCharm en administrateur."
