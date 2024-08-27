const baseAddress = Module.findBaseAddress('RocketLeague.exe');
const offset = '0x90C0F0'; // RL 1.53

Interceptor.attach(baseAddress.add(offset), {
    onEnter: function (args) {
        this.destination = Memory.readUtf16String(Memory.readPointer(args[0]));
        this.block = this.destination.includes('rl-psy.net');
    },
    onLeave: function (retval) {
        if (this.block) {
            console.log('[RocketLeague] Blocked WebSocket connection to ' + this.destination);
            retval.replace(0);
        } else {
            console.log('[RocketLeague] Allowed WebSocket connection to ' + this.destination);
        }
    }
});

console.log('Hooked WebSocket connect.');
