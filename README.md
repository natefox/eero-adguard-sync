# eero-adguard-sync
Simple script to sync eero clients to adguard

First generate your `session.cookie` with

```bash
docker run --rm -it \
    -v $PWD/session.cookie:/app/session.cookie \
    github.com/natefox/eero-adguard-sync:latest \
    login.py
```


This will create the session.cookie file. The session cookie looks like this:
```
12345678|rewfgdsgswereqwfdsadetergf
```


Then run with the session.cookie mapped to the /app dir. Adjust the other environment variables to match your environment.

```bash
docker run --rm -it \
    -v $PWD/session.cookie:/app/session.cookie \
    -e EERO_COOKIE_FILE=/app/session.cookie \
    -e ADGUARD_IP=192.168.1.50 \
    -e ADGUARD_PORT=80 \
    -e ADGUARD_LOGIN=adguardlogin \
    -e ADGUARD_PASSWORD=mypasswordhere \
    github.com/natefox/eero-adguard-sync:latest
```


Here's how I run this personally with docker-compose
```yaml
  adguardsync:
    image: github.com/natefox/eero-adguard-sync:latest
    container_name: adguardsync
    volumes:
      - /opt/docker_apps/adguardsync/session.cookie:/app/session.cookie
    environment: # could also use an env file
      - EERO_COOKIE_FILE=/app/session.cookie # default is /app/session.cookie
      - ADGUARD_IP=192.168.1.50
      # - ADGUARD_PORT=80 # default is 80
      - ADGUARD_LOGIN=adguardlogin
      - ADGUARD_PASSWORD=mypasswordhere
      # - SLEEP_TIME=3600 ## how long to sleep between syncs (seconds)
      ## this will rename things from Eero to a new name in Adguard
      - CLIENT_RENAMES=SomeDeviceIn-Eero|My-New-Device-Name
      # inlcude only these networks (semicolon delimited) if you have multiple eero networks
      - EERO_NETWORK_NAMES=Mynetwork
      # - LOG_LEVEL=info
```

TODO:
[] Figure out how I want to handle conflicts. Notably when you have a device named XX123 and then a second XX123 comes online (smart plugs are a good example here). Need to rename the first one to work with the uniquiness. Maybe just override names any time theres an IP conflict?
[] Should be deleting when IP address is None but doesnt seem to be doing that. Will investigate.
