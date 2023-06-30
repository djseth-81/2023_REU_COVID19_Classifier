from pprint import pprint

apps = {'CoronaVirus Prevention Tips': {'8ae0b378cc18e359518ad7c212e8b9d9c4d39ccc15999c28d8b3420f5fed27f5.apk': {'avRank': 1,
                                                                                                        'permissions': ['android.permission.ACCESS_NETWORK_STATE',
                                                                                                                        'android.permission.ACCESS_WIFI_STATE',
                                                                                                                        'android.permission.ACCESS_COARSE_LOCATION',
                                                                                                                        'android.permission.INTERNET',
                                                                                                                        'android.permission.FOREGROUND_SERVICE',
                                                                                                                        'android.permission.ACCESS_FINE_LOCATION'],
                                                                                                        'pkg name': 'com.newandromo.dev18179.app626260'}},
        'Coronavirus Symptoms, Causes, Treatments': {'8ae0b378cc18e359518ad7c212e8b9d9c4d39ccc15999c28d8b3420f5fed27f5.apk': {'avRank': 1,
                                                                                                                    'permissions': ['android.permission.INTERNET',
                                                                                                                                    'android.permission.ACCESS_NETWORK_STATE'],
                                                                                                                    'pkg name': 'com.mindmate.coronavirustreatments'}},
        'Pia [covid-19]': {'8ae0b378cc18e359518ad7c212e8b9d9c4d39ccc15999c28d8b3420f5fed27f5.apk': {'avRank': 1,
                                                                                            'permissions': ['com.huawei.android.launcher.permission.CHANGE_BADGE',
                                                                                                            'com.oppo.launcher.permission.READ_SETTINGS',
                                                                                                            'com.huawei.android.launcher.permission.READ_SETTINGS',
                                                                                                            'com.sonyericsson.home.permission.BROADCAST_BADGE',
                                                                                                            'android.permission.ACCESS_NETWORK_STATE',
                                                                                                            'android.permission.WAKE_LOCK',
                                                                                                            'com.huawei.android.launcher.permission.WRITE_SETTINGS',
                                                                                                            'android.permission.ACCESS_WIFI_STATE',
                                                                                                            'android.permission.READ_EXTERNAL_STORAGE',
                                                                                                            'me.everything.badger.permission.BADGE_COUNT_WRITE',
                                                                                                            'me.everything.badger.permission.BADGE_COUNT_READ',
                                                                                                            'com.htc.launcher.permission.READ_SETTINGS',
                                                                                                            'com.oppo.launcher.permission.WRITE_SETTINGS',
                                                                                                            'com.sec.android.provider.badge.permission.WRITE',
                                                                                                            'com.sonymobile.home.permission.PROVIDER_INSERT_BADGE',
                                                                                                            'android.permission.WRITE_EXTERNAL_STORAGE',
                                                                                                            'io.kodular.kcmemoire.pia_covid19.permission.C2D_MESSAGE',
                                                                                                            'android.permission.VIBRATE',
                                                                                                            'com.htc.launcher.permission.UPDATE_SHORTCUT',
                                                                                                            'android.permission.READ_APP_BADGE',
                                                                                                            'com.google.android.c2dm.permission.RECEIVE',
                                                                                                            'com.anddoes.launcher.permission.UPDATE_COUNT',
                                                                                                            'android.permission.RECEIVE_BOOT_COMPLETED',
                                                                                                            'com.sec.android.provider.badge.permission.READ',
                                                                                                            'android.permission.INTERNET',
                                                                                                            'com.majeur.launcher.permission.UPDATE_BADGE'],
                                                                                            'pkg name': 'com.piacovid19.app'}}}

apk = "8ae0b378cc18e359518ad7c212e8b9d9c4d39ccc15999c28d8b3420f5fed27f5.apk"

for app in apps:
    print(app) if apk in apps[app].keys() else print("Not cloned")

 