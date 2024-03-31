Postkvantová Blockchainová síť
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

## Blockchain
Decentralizovana sit pro bezpecne ukladani komunikace. Jednotlive zpravy se vkladaji do bloku a ty se uzamikaji hashem a nasledne se pripojuji k retezu. Plati jednoduche pravidlo: co bylo jednou ulozeno do retezu uz z nej nikdy nemuze byt vzato. Zaroven zpravy v bloku musi potvrdit alespon 51% autorit, jinak zprava nebude prijata.

#### ENDPOINTS  
O obsluhu blockchainu se stara 5 endpointu:
#### 1. Vytisk tabulky vsech nodu  
<code>/nodes/get_nodetable</code>  
GET pozadavek, ktery vrati seznam vsech nodu v blockchainu. Sit je nastavena tak, ze kazdy node ma informaci o vsech ostatnich. Se vsemi komunikuje.  
#### 2. overeni a vytisk retezu  
<code>/chain</code>  
GET pozadavek. Po zavolani node provede kontrolu spravnosti celeho retezu. Zkontroluje jestli bloky (jejich hashe) na sebe spravne navazuji a zaroven zkontroluje jestli ma kazdy blok spravne vypocitanou hash  
#### 3. Vlozeni zpravy (logu) na blockchain node  
<code>/logs/new</code>
```json  
{ 
"public_key":"sign_public_key3",  
"message":"zprava od clienta",  
"signature":"signature"   
}
```  
POST pozadavek, obsahuje JSON zpravy. Zprava se automaticky ulozi do zasobniku pro dalsi blok. Zaroven se rozdistribuje na vsechny nody v siti. Drzi se pravidlo, vsichni maji prehled o vsem a nikdo neni vys, nez ostatni.  

#### 4. zahajeni tezby  
<code>/mine/start</code>  
GET pozadavek. Impuls pro celou sit, ze ma zacit tezit dukaz pro overeni soucasneho bloku.  

#### 5. vyhodnoceni retezu v nodech  
<code>/nodes/resolve</code>  
TODO: Impuls pro celou sit. Nody si porovnaji svoje retezy a ten ktery ziska vice jak 51% se stane jedinym prezivsim  
Tento endpoint bude volan pokazde kdy se pripoji novy node k siti, a to proto aby nemusel spolehat na spravnost retezu sveho souseda, ale primo dostal vsemi potvrzeny vzorek.


#### NODE
Protoze jsou vsechny nody naprosto stejne, uvedu popis jednoho z nich. Cela sit se pak sklada z minimalne 3 nodu, ale pro vyssi uroven bezpecnosti doporucuji spustit nodu vice. 

1. Start  
Pri spusteni se vytvori objekt <b>blockchain</b> tridy <b>Blockchain</b>. Tento objekt obsahuje jak samotny retez a dalsi pomocne promenne nezbytne pro provoz, tak i radu obsluznych funkci mj. tezba, pridavani bloku, overovani retezu. 
Pred samotnym spustenim serveru (vyuziva se <b>Python Tornado</b>) se vezme z konfiguracniho souboru informace, na kterem portu a adrese ma byt server spusten a na jake adrese se nachazi nejblizsi fungujici node. Pokud zadny neni, nastavi se pro sousedni port stejna adresa, jako pro nas node. Tzn bude sam sobe sousedem. Neni to problem, protoze tuto vlastnost vyuzije jen pri svem spusteni a pote uz ji nikdy nevyuzije. Opet se tim potvrzuje pravidlo: nikdo neni nad ostatnimi. 
Jednu vterinu po spusteni serveru se node zaregistruje do site. To probehne tim zpusobem, ze na sousedni node odesle informace o sobe.  
Soused si zapise udaje o novem nodu do sve <b>node_table</b> a jeji aktualizovanou verzi odesle vsem nodum v siti. Timto zpusobem se i novy node dozvi informace o ostatnich nodech v siti. V tomto momente uz zahazuje informaci o jeho primem sousedovi, protoze nadale bude se vsemi komunikovat na stejne urovni.  

2. Pridani zpravy do zasobniku  
Jedna z velmi typickych situaci, ktera se deje je ta, ze klient blockchainove site bude chtit do ni neco zapsat. Pozadavek odesle skrz endpoint popsany vyse na jeden z nodu v siti. Ten zkontroluje, zda zprava obsahuje vsechna potrebna data a zda ji uz nedostal drive. Pokud ne, odpovida pozitivne zpatky klientovi. Zpravu si uklada k sobe do zasobniku <b>blockchain.current_logs</b> a nasledne zpravu, tak jak ji dostal, distribuje vsem nodum v siti. V pripade, ze zpravu jiz v zasobniku mel, neprovadi zadnou akci. Je zrejme, ze pokud zpravu uz predtim mel, tak ji take urcite uz predtim rozeslal. Proto nevykona nic a klientovi odpovi, ze zpravu neprijal. 

3. Tezba  
Jedna z nejvice komplexnich funkcionalit. Node v teto fazi dela nekolik veci a mnohdy najednou. 1. Provadi samotnou tezbu 2. instruuje ostatni nody, aby take zacali tezit. 3. Vyhodnocuje svoji tezbu a zaroven prijima od ostatnich nodu jejich vytezene bloky (to se deje temer jen v pripade, kdy slozitost dukazu je prilis nizka a jeho casova narocnost je mensi nez prodleni pri komunikaci po siti, realnem nasazeni se takova situace stane ojedinele). 4. Porovnava vsechny kandidaty vytezenych bloku a podle nastavenych pravidel vybira jeden jediny, ktery si uklada do retezu.  
Takze postupne:  
Po zavolani endpointu /mine/start node nejprve overi, zda by nedoslo ke kolizi v tezbe. Node nemuze tezit blok, pokud jeste nebyl dotezen blok predesly. Nefungovala by navaznost hashu. Pokud se tak nedeje, obesila vsechny nody v siti s prikazem "zacni tezit".  
On sam zacne skladat dohromady blok zprav, ke kterym prilozi hlavicku bloku. Hlavicka obsahuje index bloku, casovou znacku zacatku tezby bloku, dukaz(prozatim nastaveny na nulovou hodnotu) a hash z predesleho bloku retezu. Tento zabaleny blok odesila do funkce pro tezbu.  
Tato funkce bezi na nove vytvorenem vlaknu tak, aby neovlivnovala chod nodu. Doba tezby se odviji od narocnosti dukazu a ta byla nastavena v konfiguracnim souboru. Tezba je prirovnani pro hadani spravneho dukazu. Dukaz je cislo, ktere kdyz vlozite na stanovene misto do bloku, jeho hash bude splnovat narocnostni podminku. Napriklad ze bude zacinat ctyri nulami. Pokud bychom chteli vetsi narocnost nastavime podminku na vice pocatecnich nul. Nejde o to, ze by to nutne museli byt nuly, byt je to tak u vetsiny blockchainu, ale jde o to, ze to jsou konkretni hodnoty a to nekorespenduje s vlastnosti hashe "neodhadnutelneho vysledku". Tedy jedinym moznym zpusobem jak konkretnich hodnot dosahnout je menit vstupni data a pozorovat zda jsme ziskali pozadovany hash.  
Ukonceni tezby muze mit dva duvody 1. On sam vytezil dukaz, nebo 2. Prisla mu zprava od jineho nodu, ze on byl uspesnejsi a uz nema cenu dal tezit. V takovem pripade ukoncuje vlakno pro tezbu a prijima blok od druheho nodu.  
Pri nizke narocnosti dukazu a lokalni siti je rozdil mezi vytezenim vlastniho bloku a prijeti zpravy, nekolik malo desitek milisekund. Proto se stava, ze node ma k dispozici jak vlastni vytezeny blok, tak i jeden nebo vice bloku od sousedu. Vsechny jsou platne, ale vsechny jsou zaroven jine. Kazdy z nich obsahuje jinou casovou znacku zacatku tezby a v kazdem z nich je jiny udaj o autorovi uspesne tezby. To znamena ze kazdy ma take jiny hash a i kdyz by vsechny mohli byt pripojeny jako dalsi clanek k retezu, pro zachovani konsenzu musi byt vybran jen jeden. Jako kriterium, pro vyber takoveho kandidata je casova znacka ukonceni tezby. Tato znacka neni primo v samotnem bloku (tezim nad celym blokem, nemohu na konci pridat casovou znacku a tim kompletne ponicit kontrolni hash. Takovy blok by nebyl platnym), ale je pripojena vedle neho a node ji odesila po dokonceni tezby. Tato znacka dosahuje presnosti az jednotky milisekund a proto je pro takove kriterium vhodna. Po vybrani vhodneho kandidata se blok pripoji do retezu a node je pripraven na pokyn k dalsi tezbe. 

4. Overeni retezu  
Ve chvili kdy je potreba zkontrolovat spravnost retezu zavola se funkce valid_chain() ve tride Blockchain. Tato funkce projede blok po bloku a kontroluje dve podminky. 1. Je v kazdem bloku spravna hodnota dukazu? 2. Odpovida predchozi hash v bloku skutecne hashi predesleho bloku? Pokud jsou obe kriteria naplnena pro kazdy blok v retezu, tak je retez povazovan za validni a muze s nim byt dal zachazeno. Napriklad vzit ho pro vytahnuti zprav pro uzivatelske pouziti, nebo pro rozhodovani o hlavnim retezu v siti. 

5. Hlavni retez v siti  
Donutim vsechny prestat tezit. Zahodit praci (je to random je to jedno) Pokud nejaky node dostane informaci pozdeji nez nekdo jiny, nevadi. Proste posle vsem svuj block a jede se dal. Vsem poslu zpravu prestan tezit a od vsech pockam na odpoved "prestal jsem" tim si i overim ze ubehl dostatecny cas na to aby node ktery vytezi block ho poslal ostatnim.  
  
## co chci udelat: 
Vyresit original kyber. Je mozne to vubec rozjet ve Windows? Rozjet v linux a vytvorit si API?

Syslogger: definovat si jake logy chci z pocitace stahovat. a zda vubec. Pouzit dataset?  
napsat testy pro jednotlive algoritmy=extremne slozite: kazdy potreba zvlast. Je to nutne?  
pridat ke kazdemu zaznamu na strane klienta identifikator. zaruci ze podepsana zprava nemuze byt duplikovana  
