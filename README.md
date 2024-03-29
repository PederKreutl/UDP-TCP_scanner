# UDP/TCP skener
Cieľom projektu bolo vytvoriť sieťový TCP, UDP skener. Činnosť programu spočíva v oskenovaní portov na danom zariadení. Zariadenie a porty sú predávané ako vstupné argumenty programu, pričom zariadenie môže byť identifikované doménovým menom alebo IP adresou podporovanou vo formáte IPv4/IPv6. Implementácia takisto podporuje voliteľnú voľbu sieťového rozhrania zdrojového zariadenia. Výstupom programu je výpis stručného súhrnu o stave portov. Stav môže nadobúdať 3 hodnoty: otvorený/uzatvorený a pri protokole TCP aj filtrovaný.

## Preklad:
  ***`$ make`***
  
## Použitie:
  ***`$ ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <por-ranges> [<domain-name> | <IP-address>]`***

## Nápoveda:
  ***`$ ./ipk-scan -h`***

## Výstup:
  ***`Interesting ports on localhost (127.0.0.1):`***\
  ***`PORT     STATE`***\
  ***`21/tcp	 closed`***\
  ***`22/tcp 	 open`***\
  ***`143/tcp	 filtered`***\
  ***`53/udp	 closed`***\
  ***`67/udp	 open`***

## Výstupne kódy:
  0 - Úspešné spustenie programu\
  1 - Chybné spustenie programu\
  2 - Interná chyba v programe

## Autor:
  Peter Kruty, <xkruty00@stud.fit.vutbr.cz>
