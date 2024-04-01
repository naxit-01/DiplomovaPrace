# Blockchain service
#### Návod na spuštění  
0. Předpoklady: 
   - Python 3.12.2

1. stáhněte repozitář 
   ```bash 
   git clone -b PostChain-network https://github.com/naxit-01/DiplomovaPrace.git
   ```
2. spusťte **setup.bat**. Tento script vytvoří virtuální prostředí jazyka Python a do něj nainstaluje potřebné knihovny. Po dokončení stiskněte libovolnou klávesu.
3. Při instalaci byly vytvořené dva nové scripty. **activate_client.bat**, **activate_blockchain.bat**
5. Alespoň 3x spusťte **activate_blockchain.bat**
6. Na závěr spuťte **activate_client.bat**
7. Celou síť ovládáte pomocí příkazového okna clienta.
#### Konfigurace: 
V souboru config.ini se všechny sluzby dozvídají potřebné informace pro jejich spuštění. Služby i konfigurační soubor je napsán tak, aby mohly být všechny služby spuštěny na stejném konfiguračním souboru ale zároveň je možné pro každou službu konfigurační soubor upravit.  
Tento soubor obsahuje:  
Algoritmus pro KEM a pro podepisování zpráv. KEM musí být vybrán pro všechny služby stejný, ale podepisoací algoritmus může mít každá služba vlastní.  
Informace o sousedním nodu. Adresa a port nodu se kterým se bude komunikovat. Podstatné pouze pro klienta a node. CA tuto informaci sice načítá, ale nevyužívá.   
Složitost hashe v blockchainu. Tuto informaci využívá pouze node, který tak nastavuje složitost těžby. Tato konstanta musí být pro všechny nody stejná.  
Adresa a port certifikační autority. Tyto údaje využívají všechny služby a musí být pro všechny služby stejná. 

## Dataset
Systemove logy, ktere jsou posilany beru z data setu, ktery jsem stahnul z github repozitare https://github.com/logpai/loghub

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
"message":"zprava od clienta",  
}
```  
POST pozadavek, obsahuje JSON zpravy. Zprava se automaticky ulozi do zasobniku pro dalsi blok. Zaroven se rozdistribuje na vsechny nody v siti. Drzi se pravidlo, vsichni maji prehled o vsem a nikdo neni vys, nez ostatni.  

#### 4. zahajeni tezby  
<code>/mine/start</code>  
GET pozadavek. Impuls pro celou sit, ze ma zacit tezit dukaz pro overeni soucasneho bloku.  

#### 5. vyhodnoceni retezu v nodech  
<code>/chain/resolve</code>  
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
  