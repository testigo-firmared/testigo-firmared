# Testigo externo del registro público de FirmaRED

Este repositorio mira el registro público de [firmared.com](https://firmared.com) desde afuera, una vez por hora, y anota lo que ve. No lo administra el servidor de FirmaRED: corre en GitHub Actions, con el código de este repositorio, y cada anotación queda fechada por GitHub en un commit. Si alguna vez FirmaRED cambiara una firma ya publicada, volviera atrás una raíz o cambiara sus claves, acá quedaría escrito.

## Qué mira

El registro público de FirmaRED es un árbol de Merkle (RFC 9162) con una hoja por firma. Cada tantas horas FirmaRED publica una **raíz**: el número de firmas que contiene, el hash del árbol y la fecha, selladas con tres firmas sobre los mismos bytes:

| Sello | Algoritmo | Norma | Clave guardada acá |
|---|---|---|---|
| Clásico | Ed25519 | RFC 8032 | `claves/firmared-sello-ed25519.pem` |
| Poscuántico | ML-DSA-65 | NIST FIPS 204 | `claves/firmared-sello-mldsa65.pem` |
| Poscuántico, basado en hashes | SLH-DSA-SHA2-128s | NIST FIPS 205 | `claves/firmared-sello-slhdsa.pem` |

Cada hora, `testigo.mjs`:

1. Comprueba que las tres claves que el sitio publica en `firmared.com/claves/` sigan siendo las guardadas en `claves/`. Si cambian, lo dice.
2. Baja la última raíz (`/api/public/registro/raiz`) y comprueba los tres sellos con esas claves, usando solo el OpenSSL que trae Node (ninguna biblioteca de FirmaRED).
3. Comprueba que la raíz nueva **contenga** a la última que este testigo vio: pide la prueba de consistencia (`/api/public/registro/consistencia?de=N&a=M`) y la verifica según la RFC 9162. Así, borrar o cambiar una firma anterior quedaría a la vista.
4. Anota: `registro/corridas.jsonl` (una línea por mirada), `registro/raices.jsonl` (una línea por raíz nueva y bien verificada), `registro/ultima.json` (lo que va a comparar la próxima vez) y `ESTADO.md` (el resumen).

## Cómo comprobarlo uno mismo

Con Node 24 o posterior:

    node testigo.mjs

Con OpenSSL 3.5 o posterior, sobre la última raíz:

    curl -s https://firmared.com/api/public/registro/raiz > raiz.json
    node -e 'const j=require("./raiz.json").ultima;require("fs").writeFileSync("sth.json",JSON.stringify(j.sth));for(const [n,f] of [["ed25519",j.sello.firma],["mldsa65",j.sello.mldsa65.firma],["slhdsa",j.sello.slhdsa.firma]]) require("fs").writeFileSync("firma-"+n+".bin",Buffer.from(f,"base64"))'
    openssl pkeyutl -verify -pubin -inkey claves/firmared-sello-ed25519.pem -rawin -in sth.json -sigfile firma-ed25519.bin
    openssl pkeyutl -verify -pubin -inkey claves/firmared-sello-mldsa65.pem -rawin -in sth.json -sigfile firma-mldsa65.bin
    openssl pkeyutl -verify -pubin -inkey claves/firmared-sello-slhdsa.pem -rawin -in sth.json -sigfile firma-slhdsa.bin

Las huellas de las tres claves están en `claves/huellas.txt`, copiado del sitio el día que se creó este testigo, y en el DID de FirmaRED (`https://firmared.com/.well-known/did.json`). La raíz, además, se ancla en Bitcoin con OpenTimestamps: el comprobante de cada raíz está en `https://firmared.com/api/public/registro/raiz/<N>/ots`.

## Qué no es

No es un servicio de FirmaRED ni depende de que FirmaRED esté de acuerdo con lo que anota. Cualquiera puede copiar este repositorio y correr su propio testigo: cuantos más, mejor.
