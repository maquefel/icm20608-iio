# IMU icm20608 working example both with libiio and without

## local board

```
# ./icm20608d icm20608
```

## remote host

on board:
```
# iiod
```

on host:
```
$ ./icm20608 -u ip:<IP> icm20608
```

