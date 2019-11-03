import codecs
import sys
import frida

if __name__ == '__main__':
    session = frida.attach("RocketLeague.exe")

    with codecs.open("main.js", "r", encoding="utf8") as f:
        script_code = f.read()

    script = session.create_script(script_code)
    script.load()

    print('Script should be running, press CTRL+C to exit.')
    sys.stdin.read()
