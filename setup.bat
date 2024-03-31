python -m venv pqcvenv
call pqcvenv\Scripts\activate
call pip install -r requirements.txt
REM call git clone https://github.com/kpdemetriou/pqcrypto.git

call mkdir pqcrypto
xcopy /Y /E pqcryptoLib\* pqcrypto

call python pqcrypto\compile.py

xcopy /Y /E pqcrypto\_kem\* pqcrypto\pqcrypto\_kem
xcopy /Y /E pqcrypto\_sign\* pqcrypto\pqcrypto\_sign

rename pqcrypto pqcryptoL

echo call pqcvenv\Scripts\activate > activate_alice.bat
echo call python alice.py >> activate_alice.bat

echo call pqcvenv\Scripts\activate > activate_bob.bat
echo call python bob.py >> activate_bob.bat

echo call pqcvenv\Scripts\activate > activate_ca.bat
echo call python CA.py >> activate_ca.bat
