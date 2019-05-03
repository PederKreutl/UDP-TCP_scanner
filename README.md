--------------------------------------------------------------------------------
                    README - IPK 2. projekt (UDP/TCP skener)
--------------------------------------------------------------------------------
Preklad:
  $ make

Pouzitie:
  $ ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <por-ranges> [<domain-name> | <IP-address>]

Napoveda:
  $ ./ipk-scan -h

Vystup:
  Interesting ports on localhost (127.0.0.1):
  PORT     STATE
  21/tcp	 closed
  22/tcp 	 open
  143/tcp	 filtered
  53/udp	 closed
  67/udp	 open

Vystupne kody:
  0 - Uspesne spustenie programu
  1 - Chybne spustenie programu
  2 - Interna chyba v programe

Autor:
  Peter Kruty, <xkruty00@stud.fit.vutbr.cz>
  April 2019
  VUT FIT, Brno
