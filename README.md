# eth2crawler

## DB setup

https://stackoverflow.com/questions/16287559/mysql-adding-user-for-remote-access

```
sudo mysql -u root
CREATE DATABASE eth2nodes;
CREATE USER 'lion'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'lion'@'localhost' WITH GRANT OPTION;
```