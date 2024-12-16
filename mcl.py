# mcl.py - Minecraft Launcher
# License: do whatever you want.
# This code respects Minecraft rules. A Minecraft account is needed to use it.
# Only Minecraft java edition is supported.
# Accounts are stored in 'accounts.json'.
# The launcher/game creates files where mcl.py is located, so you may want to put mcl.py in an empty folder to keep things organized.
# Python 3.8+

HELP = """
mcl.py
mcl.py help
Show this help message.

mcl.py login [code]
If [code] is not specified, show link to Microsoft login page where you should login. After logging in, you will be redirected to a blank page that contains a code in the URL. Use the code in this command to add an account to the launcher.
Example: mcl.py login M.C507_BL2.2.U.dbf86d81-7aab-abd6-9c7d-12a04a49221b

mcl.py launch <version> [account]
mcl.py l <version> [account]
Download specified <version> if not already downloaded, refresh Minecraft token if expired and launch the game. [account] can be a username or UUID. If [account] is not specified, the first account found in accounts.json is used. If no account is found, you will be asked to login.
Example: mcl.py launch 1.8.9
Example: mcl.py launch 1.8.9 notch

mcl.py download <version>
mcl.py d <version>
Download specified <version> if not already downloaded.
Example: mcl.py download 1.8.9

mcl.py accounts
List accounts in accounts.json

mcl.py versions
List Minecraft versions in the 'versions' directory.

mcl.py manifest
Download version manifest and list all Minecraft versions with their release dates.

mcl.py refresh <account>
Resfresh the Minecraft token of the specified <account> if it has expired. [account] can be a username or UUID.
"""

import sys
import os
import json
from urllib.request import urlopen, urlretrieve, Request
from urllib.error import HTTPError
from pathlib import Path
import platform
import subprocess
from threading import Thread
from time import sleep,time
from lzma import LZMADecompressor
from zipfile import ZipFile
import traceback
import struct

VERSIONS_MANIFEST_URL = "https://launchermeta.mojang.com/mc/game/version_manifest.json"
RUNTIMES_MANIFEST_URL = "https://launchermeta.mojang.com/v1/products/java-runtime/2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json"

os.chdir(Path(sys.argv[0]).parent)

# linux, windows, osx
os_name = platform.system().lower().replace("darwin","osx")

arch = platform.machine().lower()

def pass_rules(library):
    try:
        rules = library["rules"]
    except KeyError:
        return True
    allow = False
    for rule in rules:
        if "os" not in rule or rule["os"] == os_name or ("name" in rule["os"] and rule["os"]["name"] == os_name):
            if rule["action"] == "allow":
                allow = True
            elif rule["action"] == "disallow":
                allow = False
    return allow

def get_runtime_name(version_manifest):
    try:
        return version_manifest["javaVersion"]["component"]
    except KeyError: # e.g. 1.6.4
        return "jre-legacy"

def get_runtime_os_name():
    if os_name == "windows":
        if "arm" in arch:
            return "windows-arm64"
        elif "64" in arch:
            return "windows-x64"
        else:
            return "windows-x86"
    elif os_name == "linux":
        is_python_32_bits = 8*struct.calcsize("P") == 32
        return "linux-i386" if ("86" in arch and is_python_32_bits) else "linux"
    elif os_name == "osx":
        return "mac-os-arm64" if ("arm" in arch) else "mac-os"
    else:
        raise NotImplementedError

def download(version_name):
    current_download_count = 0
    total_download_count = 0

    def get_manifest_from_url(path, url):
        nonlocal current_download_count, total_download_count
        total_download_count += 1
        manifest = urlopen(url).read()
        current_download_count += 1
        print(f"{current_download_count}/{total_download_count}", path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(manifest)
        return json.loads(manifest.decode())

    def get_manifest(path, url):
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return get_manifest_from_url(path, url)

    version_manifest_path = Path("versions")/version_name/f"{version_name}.json"

    try:
        version_manifest = json.loads(version_manifest_path.read_text())
    except FileNotFoundError:
        versions_manifest = get_manifest(Path("versions")/"versions_manifest.json", VERSIONS_MANIFEST_URL)
        version_manifest_url = next(e["url"] for e in versions_manifest["versions"] if e["id"] == version_name)
        version_manifest = get_manifest_from_url(version_manifest_path, version_manifest_url)

    done_downloading = False
    pending_downloads = []

    def queue_download(url, path, lzma_compressed=False):
        nonlocal total_download_count
        total_download_count += 1
        pending_downloads.append((url,path,lzma_compressed))

    def download_file_thread():
        nonlocal current_download_count
        while True:
            try:
                url, path, lzma_compressed = pending_downloads.pop(0)
            except: # empty
                if done_downloading:
                    return
                else:
                    sleep(0.1)
            else:
                decompressor = LZMADecompressor() if lzma_compressed else None
                path.parent.mkdir(parents=True,exist_ok=True)
                stream = urlopen(url)
                with open(path,"wb") as file:
                    while data := stream.read(0x2000):
                        file.write(decompressor.decompress(data) if lzma_compressed else data)
                current_download_count += 1
                print(f"{current_download_count}/{total_download_count}", path)


    client_jar_path = Path("versions")/version_name/f"{version_name}.jar"
    if not client_jar_path.exists():
        client_jar_url = version_manifest["downloads"]["client"]["url"]
        queue_download(client_jar_url, client_jar_path)

    natives_path = Path("versions")/version_name/"natives"
    natives_path.mkdir(parents=True, exist_ok=True)
    native_jar_paths = []

    for library in version_manifest["libraries"]:
        if not pass_rules(library):
            continue

        if "artifact" in library["downloads"].keys(): # one jar for all platform
            library_path = Path("libraries")/library["downloads"]["artifact"]["path"]
            if library_path.exists():
                continue
            library_url = library["downloads"]["artifact"]["url"]

        if "classifiers" in library["downloads"].keys(): # one jar for each platform
            classifier_key = library["natives"][os_name].replace("${arch}",("64" if "64" in arch else "32"))
            library_path = Path("libraries")/library["downloads"]["classifiers"][classifier_key]["path"]
            library_url = library["downloads"]["classifiers"][classifier_key]["url"]
            try: # check natives
                with ZipFile(library_path) as zip:
                    for name in zip.namelist():
                        if not (natives_path/name).exists():
                            zip.extract(name, natives_path)
                            print(natives_path/name)
                continue
            except FileNotFoundError:
                native_jar_paths.append(library_path)

        queue_download(library_url, library_path)

    threads = []
    for i in range(6):
        t = Thread(target=download_file_thread)
        t.start()
        threads.append(t)

    full_runtime_name = f"{get_runtime_name(version_manifest)}-{get_runtime_os_name()}"

    runtime_manifest_path = Path("runtimes")/full_runtime_name/f"{full_runtime_name}.json"
    try:
        runtime_manifest = json.loads(runtime_manifest_path.read_text())
    except FileNotFoundError:
        runtimes_manifest = get_manifest(Path("runtimes")/"runtimes_manifest.json", RUNTIMES_MANIFEST_URL)
        runtime_manifest_url = next(v[0]["manifest"]["url"] for k,v in runtimes_manifest[get_runtime_os_name()].items() if k == get_runtime_name(version_manifest))
        runtime_manifest = get_manifest_from_url(runtime_manifest_path, runtime_manifest_url)

    chmod_bin_java = False

    for item_path,item in runtime_manifest["files"].items():
        path = Path("runtimes")/full_runtime_name/item_path
        if path.exists():
            continue
        if item_path.endswith("bin/java"):
            chmod_bin_java = True
        if item["type"] != "file":
            continue
        if "lzma" in item["downloads"]:
            item_url = item["downloads"]["lzma"]["url"]
            lzma_compressed = True
        else:
            item_url = item["downloads"]["raw"]["url"]
            lzma_compressed = False
        queue_download(item_url, path, lzma_compressed)

    assets_manifest = get_manifest(Path("assets")/"indexes"/f"{version_manifest['assets']}.json", version_manifest["assetIndex"]["url"])

    objects_path = Path("assets")/"objects"
    for object in assets_manifest["objects"].values():
        hash = object["hash"]
        path = objects_path/hash[:2]/hash
        if not path.exists():
            queue_download(f"https://resources.download.minecraft.net/{hash[:2]}/{hash}", path)

    done_downloading = True

    for t in threads:
        t.join()

    # enable execution permission for the java executable
    if os_name != "windows" and chmod_bin_java:
        subprocess.run(["chmod", "+x", (Path("runtimes")/full_runtime_name/"bin"/"java").resolve()])

    for path in native_jar_paths:
        with ZipFile(path) as zip:
            zip.extractall(natives_path)
            for name in zip.namelist():
                print(natives_path/name)

def check_if_account_information_changed(account, accounts):
    def save_account():
        for e in accounts:
            if e["microsoft_refresh_token"] == account["microsoft_refresh_token"]:
                e["username"] = account["username"]
                e["uuid"] = account["uuid"]
                e["minecraft_token"] = account["minecraft_token"]
        Path("accounts.json").write_text(json.dumps(accounts))

    def account_information_changed():
        if username != account["username"] or uuid != account["uuid"]:
            print("Account information changed.")
            print(f"Old: {account['uuid']!r} {account['username']!r}")
            print(f"New: {uuid!r} {username!r}")
            account["username"] = username
            account["uuid"] = uuid
            return True

    try:
        username, uuid = minecraft_token_to_username_and_uuid(account["minecraft_token"])
    except HTTPError as e:
        if e.code == 401: # Unauthorized
            print("Minecraft token expired. Requesting a new one...")
            try:
                microsoft_token = microsoft_refresh_token_to_microsoft_token(account["microsoft_refresh_token"])
                account["minecraft_token"] = microsoft_token_to_minecraft_token(microsoft_token)
            except HTTPError as e2:
                traceback.print_exc()
                print("Microsoft refresh token may have expired. Login again to get a new token.")
                print("Response body:", e2.read())
            except Exception:
                traceback.print_exc()
            else:
                try:
                    username, uuid = minecraft_token_to_username_and_uuid(account["minecraft_token"])
                except HTTPError as e3:
                    traceback.print_exc()
                    print("Response body:", e3.read())
                    if e3.code == 401: # Unauthorized
                        print("New Minecraft token expired???")
                except Exception:
                    traceback.print_exc()
                else:
                    account_information_changed()
                    save_account() # we always save here because the minecraft_token has changed
        else:
            traceback.print_exc()
            print("Response body:", e.read())
    except Exception:
        traceback.print_exc()
    else:
        if account_information_changed():
            save_account()

def find_account(username_or_uuid, accounts):
    username_or_uuid = username_or_uuid.lower().replace("-","")
    try:
        return next(e for e in accounts if username_or_uuid == e["uuid"].lower().replace("-","") or username_or_uuid == e["username"].lower())
    except Exception as e:
        e.add_note(f"Account {username_or_uuid!r} not found in accounts.json")
        raise e

def launch(version_name, username_or_uuid):
    print("Checking if any file is missing...")
    download(version_name)

    accounts = json.loads(Path("accounts.json").read_text())

    if username_or_uuid is None:
        print("No account was specified, first one found in accounts.json will be used.")
        account = accounts[0]
    else:
        account = find_account(username_or_uuid, accounts)

    print("Using account:", account["uuid"], account["username"])

    print("Checking if account information has changed...")
    check_if_account_information_changed(account, accounts)

    version_manifest = json.loads((Path("versions")/version_name/f"{version_name}.json").read_text())

    runtime_dir_path = Path("runtimes")/f"{get_runtime_name(version_manifest)}-{get_runtime_os_name()}"
    java_executable_path = (runtime_dir_path/"bin"/("javaw" if os_name == "windows" else "java")).resolve()
    natives_path = str((Path("versions")/version_name/"natives").resolve())
    client_jar_path = (Path("versions")/version_name/f"{version_name}.jar").resolve()

    lib_jar_paths = []
    for library in version_manifest["libraries"]:
        if not pass_rules(library):
            continue
        if "artifact" in library["downloads"]:
            lib_jar_paths.append(str((Path("libraries")/library["downloads"]["artifact"]["path"]).resolve()))
    lib_jar_paths.append(str(client_jar_path))
    if os_name == "windows":
        lib_jar_paths = ";".join(lib_jar_paths)
    else:
        lib_jar_paths = ":".join(lib_jar_paths)

    arg_vars = {
        "${auth_player_name}": account["username"],
        "${version_name}": version_name,
        "${game_directory}": str(Path("").resolve()),
        "${assets_root}": str(Path("assets").resolve()),
        "${assets_index_name}": version_manifest["assetIndex"]["id"],
        "${auth_uuid}": account["uuid"],
        "${auth_access_token}": account["minecraft_token"],
        "${user_properties}": "{}",
        "${user_type}": "msa",
        "${auth_session}": f"token:{account['minecraft_token']}:{account['uuid']}",
        "${version_type}": version_manifest["type"],
        "${natives_directory}": natives_path,
        "${classpath}": lib_jar_paths,
    }

    def process_args(args):
        processed_args = []
        for i,arg in enumerate(list(args)):
            if isinstance(arg, dict):
                continue #TODO

            for k,v in arg_vars.items():
                arg = arg.replace(k,v)

            if "${" in arg:
                print("Failed to parse", arg)
                if arg.startswith("${"):
                    processed_args.pop(-1)
                continue

            processed_args.append(arg)

        return processed_args

    try:
        jvm_args = version_manifest["arguments"]["jvm"]
    except:
        jvm_args = []

        if os_name == "windows":
            jvm_args.append("-XX:HeapDumpPath=MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump")
        elif os_name == "osx":
            jvm_args.append("-XstartOnFirstThread")

        jvm_args += [
            f"-Djava.library.path={natives_path}",
            f"-Dminecraft.client.jar={client_jar_path}",
            "-cp",
            lib_jar_paths,
        ]
    else:
        jvm_args = process_args(jvm_args)

    #if os_name == "linux":
    #    for p in [runtime_dir_path/"lib"/"amd64", runtime_dir_path/"lib"/"i386", runtime_dir_path/"lib"]:
    #        if p.exists():
    #            jvm_args.append(f"-Dorg.lwjgl.librarypath={p.resolve()}")
    #            break

    game_args = version_manifest["minecraftArguments"].split() if "minecraftArguments" in version_manifest else version_manifest["arguments"]["game"]
    game_args = process_args(game_args)

    # arg order: jvm (json), jvm (non-json), logging (json), mainClass (json), game (json)
    args = [java_executable_path] + jvm_args + [version_manifest["mainClass"]] + game_args
    proc = subprocess.Popen(args)
    print(f"Launching Minecraft version {version_name} with process ID {proc.pid}.")
    #proc.wait()

def microsoft_refresh_token_to_microsoft_token(microsoft_refresh_token):
    r = json.load(urlopen(Request(method="POST", url="https://login.live.com/oauth20_token.srf", data=f"scope=service::user.auth.xboxlive.com::MBI_SSL&client_id=00000000402B5328&grant_type=refresh_token&refresh_token={microsoft_refresh_token}".encode())))
    microsoft_token = r["access_token"]
    return microsoft_token

def microsoft_token_to_minecraft_token(microsoft_token):
    r = json.load(urlopen(Request(method="POST", url="https://user.auth.xboxlive.com/user/authenticate", data=('{"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": "%s"}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}' % microsoft_token).encode(), headers={"Content-Type":"application/json"})))
    xbl_token = r["Token"]

    r = json.load(urlopen(Request(method="POST", url="https://xsts.auth.xboxlive.com/xsts/authorize", data=('{"Properties":{"SandboxId":"RETAIL","UserTokens":["%s"]},"RelyingParty":"rp://api.minecraftservices.com/","TokenType":"JWT"}' % xbl_token).encode(), headers={"Content-Type":"application/json"})))
    xsts_userhash = r["DisplayClaims"]["xui"][0]["uhs"]
    xsts_token = r["Token"]

    r = json.load(urlopen(Request(method="POST", url="https://api.minecraftservices.com/authentication/login_with_xbox", data=('{"identityToken":"XBL3.0x=%s;%s"}' % (xsts_userhash,xsts_token)).encode(), headers={"Content-Type":"application/json"})))
    minecraft_token = r["access_token"]

    return minecraft_token

def microsoft_login_code_to_microsoft_token_and_microsoft_refresh_token(code):
    r = json.load(urlopen(Request(method="POST", url="https://login.live.com/oauth20_token.srf", data=('client_id=00000000402B5328&scope=service::user.auth.xboxlive.com::MBI_SSL&code=%s&redirect_uri=https://login.live.com/oauth20_desktop.srf&grant_type=authorization_code' % code).encode())))
    microsoft_token = r["access_token"]
    microsoft_refresh_token = r["refresh_token"]
    return microsoft_token, microsoft_refresh_token

def minecraft_token_to_username_and_uuid(minecraft_token):
    r = json.load(urlopen(Request("https://api.minecraftservices.com/minecraft/profile", headers={"Authorization": f"Bearer {minecraft_token}"})))
    username = r["name"]
    uuid = r["id"]
    return username, uuid

def login(code):
    microsoft_token, microsoft_refresh_token = microsoft_login_code_to_microsoft_token_and_microsoft_refresh_token(code)
    minecraft_token = microsoft_token_to_minecraft_token(microsoft_token)
    username, uuid = minecraft_token_to_username_and_uuid(minecraft_token)
    try:
        accounts = json.loads(Path("accounts.json").read_text())
    except FileNotFoundError:
        accounts = []
    else:
        for account in list(accounts):
            if uuid == account["uuid"]:
                accounts.remove(account)
                break
    accounts.append({"username": username, "uuid": uuid, "minecraft_token": minecraft_token, "microsoft_refresh_token": microsoft_refresh_token})
    Path("accounts.json").write_text(json.dumps(accounts))

    print("Login successful:", uuid, username)

def ensure_logged_in():
    if not Path("accounts.json").exists():
        raise RuntimeError(f"File 'accounts.json' not found. Login before playing {sys.argv[2]}")

if __name__ == "__main__":
    sys.argv += [None]*3
    if sys.argv[1] == "launch" or sys.argv[1] == "l":
        ensure_logged_in()
        launch(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "download" or sys.argv[1] == "d":
        ensure_logged_in()
        download(sys.argv[2])
    elif sys.argv[1] == "login":
        code = sys.argv[2]
        if code is None:
            print("Login at https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&response_type=code&scope=service::user.auth.xboxlive.com::MBI_SSL")
            print("After logging in, you will be redirected to a blank page that contains a code in the URL. Use the code in the login command to add an account to the launcher.")
        else:
            login(code)
    elif sys.argv[1] == "accounts":
        for account in json.loads(Path("accounts.json").read_text()):
            print(account["uuid"], account["username"])
    elif sys.argv[1] == "versions":
        for p in Path("versions").iterdir():
            if p.is_dir():
                print(p.name)
    elif sys.argv[1] == "manifest":
        for version in json.load(urlopen(VERSIONS_MANIFEST_URL))["versions"]:
            print(version["releaseTime"], version["id"])
    elif sys.argv[1] == "refresh":
        username_or_uuid = sys.argv[2]
        accounts = json.loads(Path("accounts.json").read_text())
        account = find_account(username_or_uuid, accounts)
        check_if_account_information_changed(account, accounts)
    else:
        print(HELP)
