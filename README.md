# DeStringCare
## What is it?
It is a tool for extracting StringCare obfuscated secrets in Android apk files.
Some of these StringCare protected secrets may contain API addresses and API keys.

*Warning*: It is not recommended to store important API keys on the client-side, especially the keys to third party services.
A better approach is to have your own API service, and create unique API keys for each app user.
This allows to revoke API keys and banning user if necessary.

## Installation
```bash
pip install DeStringCare
```

## How to use it?
1. First download a Android apk.
    * Use a website like https://apkpure.com/ (beware that the app may be tampered with, and so not recommended).
    * Use [GPlayCli](https://github.com/matlink/gplaycli) / [GPlayWeb](https://github.com/matlink/gplayweb) to download using your own Gmail credentials.
    * Use `adb` tool which pulls the `apk` from your Android device or emulator.
        1. Download the app via Google Play store to your Android device or emulator.
        2. List packages and find the app you want.
            ```bash
            adb shell pm list packages
            ```
        3. Print path to the apk file.
            ```bash
            adb shell pm path
            ```
        4. Pull the apk file.
            ```bash
            adb pull /full/path/to/the.apk
            ```

2. Extract the StringCare secrets.
    ```bash
    destringcare Appname_v1.0.2494.apk
    ```

    You will get an output as JSON file:
    ```json
    {
        "mixpanel_api_key": "7b23daa71cdbb9e6d07f29a36de960f3"
    }
    ```

## How to resign StringCare secrets?
```bash
destringcare --resign Appname_v1.0.2494.apk
```

It loads the first key from the keystore file `~/.android/debug.keystore`.

Then it reencrypts the apk secrets and saves it as an xml file in `resigned-strings.xml`.

Resigning the StringCare secrets with your own key allows you to repackage the application and use it in your Android device.
You would need to replace the original `strings.xml` with `resigned-strings.xml` file.


## Where the resigned version can be used?
Using `apktool` it is possible to decode an application and to repackage it later again.

As it is necessary to resign the application in order for it to work in Android,
it will be also necessary to update the StringCare protected file with a new signing key.
  
Typical workflow:
1. Decode the apk using `apktool` into `apk` directory.
    ```bash
    apktool d Appname_v1.0.2494.apk -o apk
    ```

2. Replace StringCare protected xml file at path `apk/res/values/strings.xml`.
    
    It may contain a line like the following:
    ```xml
    <string name="mixpanel_api_key">367E864309B5E7E3E6642483AF380497...</string>
    ```

3. Rebuild the apk.
    ```bash
    apktool b -d apk -o app-unsigned.apk
    ```

4. Resign the apk.
    ```bash
    jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore ~/.android/debug.keystore -storepass android test.apk androiddebugkey
    ```

5. Zipaligning the apk.
    ```bash
    zipalign -v 4 app-unsigned.apk app.apk
    ```

## How to contribute?
If you have questions or enhancement ideas, **open an issue**.

If you have made improvements to the code, create a **merge request**.
