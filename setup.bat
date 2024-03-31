python -m venv postchainvenv
call postchainvenv\Scripts\activate
call pip install -r requirements.txt

REM A - pokub nemam zdrojove soubory knihovny pqcrypto
call git clone https://github.com/kpdemetriou/pqcrypto.git

REM B - pokub mam zdrojeve soubory knihony pqcrypto ve slozce pqcryptoLib
REM call mkdir pqcrypto
REM xcopy /Y /E pqcryptoLib\* pqcrypto

call python pqcrypto\compile.py

xcopy /Y /E pqcrypto\_kem\* pqcrypto\pqcrypto\_kem
xcopy /Y /E pqcrypto\_sign\* pqcrypto\pqcrypto\_sign

rename pqcrypto pqcryptoL

echo call postchainvenv\Scripts\activate > activate_agent.bat
echo call python agent.py >> activate_agent.bat

echo call postchainvenv\Scripts\activate > activate_node.bat
echo call python node.py >> activate_node.bat

echo call postchainvenv\Scripts\activate > activate_ca.bat
echo call python CA.py >> activate_ca.bat

pause