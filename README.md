PQC service

# Diplomová Práce
Praktická část se skládá ze dvou samostně fungujících systémů a poté jednoho, který vše propojuje do jednoho celku.   
První částí je mikroslužba pro posílání šifrovaných zpráv. Skládá se z pseudo certifikační autority (tato CA nedosahuje všech kvalit, kladených na CA, ale cílem DP není navrhnout vlastní, nebo použít cizí CA), klienta a serveru. Soubory jsou CA.py, client.py, server.py Více o této části níže.   
Druhou částí mé DP je Blockchain. Jeho jediný soubor se nazývá blockchain.py a pro plnou funkcionalitu je potřeba ho spustit alespoň 3x. Vše popsáno v kapitole Blockchain.   
V cílové infrastruktuře zaujímají blockchain.py a server.py stejnou pozici. Jejich sloučení dohromady je provedeno v souboru node.py. Pro ukázání celkové funkcionality je tedy potřeba spusti CA.py, node.py (alespoň 3x) a na závěr client.py. Ten může být spouštěn v libovolném počtu, ale pro ukázání funkcionality ho stačí spustit pouze jednou.  

#### Konfigurace: 
V souboru config.ini se všechny sluzby dozvídají potřebné informace pro jejich spuštění. Služby i konfigurační soubor je napsán tak, aby mohly být všechny služby spuštěny na stejném konfiguračním souboru ale zároveň je možné pro každou službu konfigurační soubor upravit.  
Tento soubor obsahuje:  
Algoritmus pro KEM a pro podepisování zpráv. KEM musí být vybrán pro všechny služby stejný, ale podepisoací algoritmus může mít každá služba vlastní.  
Informace o sousedním nodu. Adresa a port nodu se kterým se bude komunikovat. Podstatné pouze pro klienta a node. CA tuto informaci sice načítá, ale nevyužívá.   
Složitost hashe v blockchainu. Tuto informaci využívá pouze node, který tak nastavuje složitost těžby. Tato konstanta musí být pro všechny nody stejná.  
Adresa a port certifikační autority. Tyto údaje využívají všechny služby a musí být pro všechny služby stejná. 

## Šifrovaná komunikace  
Mikroslužba pro odesílání zpráv od klienta na server. Veškerá komunikace, až na jedinou výjimku, popsanou níže, je šifrovaná a podepisovaná unikátním podepisovacím klíčem. Jak KEM algoritmy pro výměnu symetrického klíče, tak podepisovací algoritmy splňují nároky na odolnost vůči kvantovým počítačům. Tyto algoritmy byly vybrány v rámci NIST POST QUANTUM soutěže. Algoritmy byly brány z dostupných zdrojů a cílem DP byla jejich implementace v praxi.  
Pro odeslání jediné zprávy je potřeba splnit několik dílčích aktivit, které nejprve popíšu a poté vysvětlím jak na sebe navazují aby mohla být zpráva správně odeslána.  
  
<b>JWT (Json web token)</b>  
je ustálený standard pro podepisovaní zpráv. Veřejné knihovny pro práci s jwt jsem nepoužil, protože jsem nenašel takovou, která umožňuje přiložit vlastní podepisovací algoritmus, proto jsem napsal vlastní implementaci jwt s ohledem na kompabilitu s veřejnou Python knihovnou PyJWT. Součástí implementace jsou dvě funkce. První je jwt.encode(payload, key, alg) vytvoří podepsaný jwt. Parametry této funkce jsou: payload (zpráva kterou chceme odeslat a další atributy), klíč, kterým chceme zprávu podepsat a název podepisovacího algoritmu. Druhá funce jwt.decode(jwt, public_key, alg=None) slouží k dekódování jwt formátu. Nejprve ale ověří zda souhladí podpis se zprávou a až pokud ano, tak rozbalí a vrátí zprávu. Protože jwt hlavička obsahuje informace o použitém podepisovacím algoritmu, není parametr alg důležitý a může se funce volat bez něj. Ovšem pro dodržení kompatibilty s PyJWT, jsem možnost volby podepisovacího algoritmu zahrnul.  

<b>Definování symetrického klíče:</b>  
tato funkcionalita naváže spojení s druhou stranou a vzájemně si si vymění informace takovým způsobem, aby výsledkem byl symetrický klíč, který ovšem nebyl poslán po síti, a tedy nikdo kromě zúčastněných stran o něm nemůže vědět. Inicializující strana nejprve vygeneruje pomoci KEM algoritmu pár veřejného a privátního klíče. Poté veřejný klíč odešle druhé straně. Ta vezme veřejná klíč a s využitím KEM algoritmu vygeneruje ciphertext a symetrický klíč. Klíč si uloží pro budoucí použití a ciphertext odešle zpět první straně. První strana vezme ciphertext, privátní klíč a s využitím KEM algoritmu vygeneruje vlastní, totožný symetrický klíč. Jednotlivé zprávy jsou podepsány privátním klíčem jednotlivých stran. Je jediný případ, kdy zpráva podepsaná není, a to když komunikace probíhá mezi certifikační autoritou a službou, která se právě spustila a dotazuje se CA na vlastní podepisovací privátní klíč. Tehdy zpráva podepsaná není, ale pokud bychom použili opravdovou CA, tak by se služba musela jinak, dodatečně autentizovat. Zpráva se ciphertextem zpět od CA už samozřejmě podepsaná je, protože součástí zdrojového kódu služby (klient/node/server) je i soubor s veřejným klíčem CA.  

<b>Získání privatního klíče:</b>  
částečně jsem tuto funkcionalitu vysvětlil o odstavec výše. Tato komunikace proběhne pro každou službu (kromě CA, která je sama sobě autoritou a nikoho jiného se neptá) pouze jednou a to ve chvíli, kdy se služba spustí. Služba zavolá funkci get_sign_private_key(my_address, CA, ALGORITHM). Parametry my_adress, CA obsahují informace o adrese a portu služby a certifikační autority. A parametr ALGORITHM obasuje názvy algoritmů, které se při komunikaci budou využívat. Výsledkem je podepisovací privátní klíč na straně služby, která o klíč žádala a uložený certifikát o službě na straně CA.  
  
<b>Dotaz na veřejný klíč:</b>  
tato funkcinalita umožňuje všem službám se zeptat certifikační autority na veřejný klíč požadovaného subjektu. Tedy pokud subjekt A odešle podepsanou zprávu službě B, tak tato služba se dotáže CA na veřejný klíč subjektu A, kterým následně ověří validitu přijaté zprávy od subjektu A. Provádějicí funkcí je ask_public_key(subject, sign_private_key, my_address, CA, ALGORITHM). Parametr subjekt udává název, pod kterým je subjekt uložen u certifikační autority. V mé DP se jedná o ip adresu:port. Parametr sign_private_key je privátním podepisovacím klíčem služby, která se dotazuje CA. Parametry my_address, CA a ALGORITHM udávají stejné informace jako v předchozím případě. Veškerá komunikace, jako i v ostatních případech je podepisována a šifrována.  
  
<b>Odeslání zprávy:</b>  
konečne se dostáváme do závěru celé této kapitoly, kdy sloučím všechny předchozí funkcionality do jedné, tak aby klient dokázal odeslat zprávu serveru.  
Klient zavolá funkci send_request(ip_address, port, payload, sign_private_key, my_address, CA, ALGORITHM, request), která se o veškerou komunikaci a odeslání zprávy postará. Obsahuje relativně hodně parametrů, ale všechny jsou naprosto podstatné. Ip_address a port jsou informace o cílové straně, kam se bude zpráva posílat. Payload obsahuje vlastní zprávu, kterou klient chce cílové straně odeslat. Sign_private_key je privátní podepisovací klíč klienta. Tento klíč si vyjednal při jeho spuštění. my_address a CA jsou informace o adresách a portech klienta a certifikační autority. ALGORITHM jsou názvy KEM a podepisovacích algoritmů, které se při komunikaci budou využívat a request udává jaký typ zprávy se bude odesílat. V části, která ukazuje mikroslužbu šifrování komunikace je jediný možný typ zprávy a tím je "message".  
Teď bych rád vysvětlil co přesně funkce send_request dělá:  
1. zeptá se na veřejný klíč serveru, kam odesílá zprávu.
2. vyjedná se serverem symetrický klíč
3. zakóduje zprávu do jwt formátu. (pro připomenutí: jwt obsahuje podpis)
4. zašifruje jwt pomocí symetrického klíče.
5. odešle zašifrovaný jwt
6. vyčká na odpověď od serveru.
7. pomocí symetrického klíče dešifruje odpověď
8. dekóduje přijatý jwt formát (to zahrnuje i kontrolu podpisu)
9. vrátí klientovi přijatou odpověď od serveru. 

To je ze strany klienta vše. Na straně CA a serveru, probíhá velmi podobná činnost. Všechny služby sdílí stejné funkce, takže si dovolím jejich činnost nevysvětlit. Navíc jsem se jim už částečně věnoval, když jsem popisoval samotné funkcionality.  

