# DeStringCare
## What is it?
It is a tool for extracting StringCare obfuscated secrets in Android apk files. Some of these StringCare protected secrets may contain API addresses and API keys.

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
2. Decode the apk using `apktool` into `apk` directory.
    ```bash
    apktool d Appname_v1.0.2494.apk -o apk
    ```

3. Find StringCare protected xml files.
    One place where it can be is in `apk/res/values/strings.xml`.
    
    It may contain a line like the following:
    ```xml
    <string name="mixpanel_api_key">367E864309B5E7E3E6642483AF380497...</string>
    ```
4. Extract the StringCare secrets.
    ```bash
    destringcare Appname_v1.0.2494.apk apk/res/values/strings.xml
    ```

    You will get an output as JSON file:
    ```json
    {
        "mixpanel_api_key": "7b23daa71cdbb9e6d07f29a36de960f3"
    }
    ```

## How to resign StringCare secrets?
```bash
destringcare --resign Appname_v1.0.2494.apk apk/res/values/strings.xml
```

It loads the first key from the keystore file `~/.android/debug.keystore`.

Then it reencrypts the apk secrets in the xml file and saves it into `resigned-strings.xml`.

Resigning the StringCare secrets with your own key allows you to repackage the application and use it in your Android device.
You would need to replace the original `strings.xml` with `resigned-strings.xml` file.

## How to contribute?
If you have questions or enhancement ideas, **open an issue**.

If you have made improvements to the code, create a **merge request**.
