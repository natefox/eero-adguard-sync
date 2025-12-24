# eero-adguard-sync
Simple script to sync eero clients to adguard

This is how I use it locally
```yaml
  adguardsync:
    image: github.com/natefox/eero-adguard-sync:latest
    container_name: adguardsync
    volumes:
      - /opt/docker_apps/adguardsync/session.cookie:/app/session.cookie
    environment: # could also use an env file
      - EERO_COOKIE_FILE=/app/session.cookie
      - ADGUARD_IP=192.168.1.50
      # - ADGUARD_PORT=80
      - ADGUARD_LOGIN=admin
      - ADGUARD_PASSWORD=mypasswordhere
      # - SLEEP_TIME=3600
      # - CLIENT_RENAMES="old_name|new_name,old_name2|new_name2" # case sensitive

```