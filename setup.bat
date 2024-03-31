python -m venv blockchainvenv
call blockchainvenv\Scripts\activate
pip install tornado
pip install requests

echo call blockchainvenv\Scripts\activate > activate_blockchain.bat
echo call python blockchain.py >> activate_blockchain.bat

echo call blockchainvenv\Scripts\activate > activate_client.bat
echo call python client.py >> activate_client.bat

pause
