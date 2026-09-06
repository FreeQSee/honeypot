#!/bin/bash

clean_file() {
  chattr -ia "$1"
  grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' "$1" >/tmp/clean_file
  mv -f /tmp/clean_file "$1"
}

systemctl disable c3pool_miner
systemctl stop c3pool_miner
systemctl disable bot.service
systemctl stop bot.service

chattr -ia /var/spool/cron/crontabs
for user_cron in /var/spool/cron/crontabs/*; do
  [ -f "$user_cron" ] && clean_file "$user_cron"
done

for system_cron in /etc/crontab /etc/crontabs; do
  [ -f "$system_cron" ] && clean_file "$system_cron"
done

for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  chattr -ia "$dir"
  for system_cron in "$dir"/*; do
    [ -f "$system_cron" ] && clean_file "$system_cron"
  done
done

clean_file /etc/anacrontab
crontab -l 2>/dev/null | grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' | crontab -

curr_dir=$(pwd -P)
for dir in /tmp /var/tmp /dev/shm; do
  [ -d "$dir" ] || continue
  if ! echo "$curr_dir" | grep -q "$dir"; then
    find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  fi
done

clean_file ~/.bashrc
clean_file ~/.bash_profile
clean_file ~/.profile
