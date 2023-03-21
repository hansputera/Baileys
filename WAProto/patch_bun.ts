if (typeof global.Bun === 'undefined') throw new Error('Only Bun!');

(async() => {
    const transpiler = new Bun.Transpiler();
    let waProto = await Bun.file('./index.js').text();

    waProto = transpiler.transformSync(waProto, 'js');
    await Bun.write('./index.js', waProto);
    console.log('WAProto/index.js patched');

    waProto = await Bun.file('./nindex.d.ts').text();
    waProto = transpiler.transformSync(waProto, 'ts');
    console.log('WAProto/index.d.ts patched');
})()
