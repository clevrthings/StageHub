# StageHub Runbook

## Starten
Voer uit vanuit de project-root:

```sh
nohup .venv/bin/python app.py > /tmp/stagehub_server.log 2>&1 & echo $!
```

Dit geeft de PID terug. StageHub hoort daarna te luisteren op poorten `80`, `443` en `8443`.

Controle:

```sh
lsof -nP -iTCP -sTCP:LISTEN | rg 'Python|:80|:443|:8443'
```

Live logs:

```sh
tail -f /tmp/stagehub_server.log
```

## Stoppen
Stop de server met de PID die je bij starten kreeg:

```sh
kill <PID>
```

Als je de PID kwijt bent, zoek die dan zo op:

```sh
lsof -nP -iTCP:8443 -sTCP:LISTEN
```

## Pi CLI (installed system)

Beheer op de Raspberry Pi via:

```sh
stagehub start
stagehub stop
stagehub restart
stagehub status
stagehub update
stagehub expose
stagehub uninstall
```
