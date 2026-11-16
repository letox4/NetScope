/*
 * NetScope - Sonda numérica de solo lectura para Frida
 *
 * Esta plantilla observa valores escalares de argumentos y retornos
 * configurados. No desreferencia punteros ni modifica memoria o argumentos.
 *
 * Antes de usarla:
 * 1. Elige "native" o "il2cpp" en CONFIG.mode.
 * 2. Completa el nombre del módulo/exportación o los datos de la clase/método.
 * 3. Usa únicamente una aplicación propia o para la que tengas autorización.
 * NetScope puede inyectar CONFIG al ejecutar la sonda desde su GUI.
 */
'use strict';

/* NETSCOPE_CONFIG_INJECTION */
const CONFIG = typeof globalThis.NETSCOPE_CONFIG === 'object'
    ? globalThis.NETSCOPE_CONFIG
    : {
    // "native" sirve para una función exportada de una biblioteca nativa.
    // "il2cpp" requiere cargar frida-il2cpp-bridge antes de este script.
    mode: 'native',

    native: {
        moduleName: 'GameAssembly.dll',
        exportName: 'Example_ReadNumericState',
        argumentIndex: 0,
        argumentType: 'int32',
        returnType: 'int32',
    },

    il2cpp: {
        assemblyName: 'Assembly-CSharp',
        namespaceName: 'Example',
        className: 'DiceController',
        methodName: 'GetResult',
        // Número de parámetros administrados; ayuda a resolver sobrecargas.
        argumentCount: 0,
        // Índice en los argumentos nativos: instancia en 0 para métodos
        // de instancia; para métodos estáticos, normalmente el primer
        // parámetro administrado está en 0.
        argumentIndex: 0,
        argumentType: 'int32',
        returnType: 'int32',
    },
    };

function logInfo(message) {
    console.log('[NetScope sonda] ' + message);
}

function logError(message) {
    console.error('[NetScope sonda] ERROR: ' + message);
}

function readScalar(value, valueType) {
    if (valueType === 'int32') return value.toInt32();
    if (valueType === 'uint32') return value.toUInt32();
    if (valueType === 'pointer') return value.toString();
    throw new Error('Tipo escalar no compatible: ' + valueType);
}

function emitObservation(subject, phase, values, domain) {
    send({
        event: 'function_observation',
        subject: subject,
        phase: phase,
        domain: domain,
        values: values,
    });
}

function detectRuntimeMarkers() {
    const names = Process.enumerateModules().map(
        module => module.name.toLowerCase());
    const markers = [];
    if (names.some(name =>
            ['clr.dll', 'coreclr.dll', 'mscoree.dll', 'hostfxr.dll']
                .includes(name))) {
        markers.push('dotnet');
    }
    if (names.includes('jvm.dll')) markers.push('java');
    if (names.some(name =>
            ['mono.dll', 'mono-2.0-bdwgc.dll'].includes(name))) {
        markers.push('mono_runtime');
    }
    if (names.some(name =>
            name.includes('electron') || name === 'node.dll' ||
            name === 'libnode.dll')) {
        markers.push('electron_or_node');
    }
    if (names.includes('gameassembly.dll')) markers.push('unity_il2cpp');
    if (names.includes('unityplayer.dll')) markers.push('unity');
    if (names.some(name =>
            name.includes('unreal') || name.startsWith('ue4') ||
            name.startsWith('ue5'))) {
        markers.push('unreal');
    }
    return markers;
}

function emitDiagnosticProfile() {
    send({
        event: 'diagnostic_profile',
        architecture: Process.arch,
        pointer_size: Process.pointerSize,
        runtime_markers: detectRuntimeMarkers(),
    });
}

function attachNativeHook() {
    const config = CONFIG.native;
    const module = Process.findModuleByName(config.moduleName);

    if (module === null) {
        throw new Error('No se encontró el módulo "' + config.moduleName + '".');
    }

    const address = module.findExportByName(config.exportName);
    if (address === null) {
        throw new Error(
            'No se encontró la exportación "' + config.exportName +
            '" en "' + config.moduleName + '".'
        );
    }

    if (!Number.isInteger(config.argumentIndex) || config.argumentIndex < 0) {
        throw new Error('native.argumentIndex debe ser un entero no negativo.');
    }

    logInfo(
        'Conectando a ' + config.moduleName + '!' + config.exportName +
        ' en ' + address + ' (solo lectura).'
    );
    const subject = config.moduleName + '!' + config.exportName;

    Interceptor.attach(address, {
        onEnter(args) {
            try {
                const value = readScalar(
                    args[config.argumentIndex],
                    config.argumentType || 'int32');
                const values = {};
                values['arg' + config.argumentIndex] = value;
                emitObservation(
                    subject, 'entry', values,
                    'native_function');
                logInfo('onEnter: argumento[' + config.argumentIndex + '] = ' + value);
            } catch (error) {
                logError('No se pudo leer el argumento: ' + error.message);
            }
        },

        onLeave(retval) {
            try {
                const value = readScalar(retval, config.returnType || 'int32');
                emitObservation(
                    subject, 'return', {return: value}, 'native_function');
                logInfo('onLeave: valor de retorno = ' + value);
            } catch (error) {
                logError('No se pudo leer el valor de retorno: ' + error.message);
            }
        },
    });

    logInfo('Hook nativo activo.');
}

function attachIl2CppHook() {
    if (typeof Il2Cpp === 'undefined') {
        throw new Error(
            'No está disponible Il2Cpp. Carga frida-il2cpp-bridge antes ' +
            'de observe_numeric.js.'
        );
    }

    const config = CONFIG.il2cpp;
    if (!Number.isInteger(config.argumentIndex) || config.argumentIndex < 0) {
        throw new Error('il2cpp.argumentIndex debe ser un entero no negativo.');
    }

    Il2Cpp.perform(function () {
        try {
            const image = Il2Cpp.domain.assembly(config.assemblyName).image;
            const fullClassName = config.namespaceName
                ? config.namespaceName + '.' + config.className
                : config.className;
            const klass = image.class(fullClassName);
            const method = klass.method(config.methodName, config.argumentCount);
            const address = method.virtualAddress;

            if (address.isNull()) {
                throw new Error('El método no tiene una dirección nativa válida.');
            }

            logInfo(
                'Conectando a ' + config.assemblyName + '!' + fullClassName +
                '.' + config.methodName + ' en ' + address + ' (solo lectura).'
            );
            const subject = config.assemblyName + '!' + fullClassName +
                '.' + config.methodName;

            Interceptor.attach(address, {
                onEnter(args) {
                    try {
                        const raw = args[config.argumentIndex];
                        const values = {};
                        // For instance methods, arg[0] is `this` (object pointer).
                        if (config.argumentIndex === 0 &&
                                config.argumentCount === 0) {
                            values['this'] = raw.toString();
                        } else {
                            values['arg' + config.argumentIndex] = readScalar(
                                raw, config.argumentType || 'int32');
                        }
                        emitObservation(
                            subject, 'entry', values, 'managed_function');
                        logInfo(
                            'onEnter: ' + JSON.stringify(values)
                        );
                    } catch (error) {
                        logError('No se pudo leer el argumento IL2CPP: ' + error.message);
                    }
                },

                onLeave(retval) {
                    // El retorno de métodos IL2CPP puede ser un puntero a un
                    // objeto C# (p. ej. DiceRollResult) o un valor crudo
                    // (int de DeterminatedRandom.Next / InternalSample). En
                    // x64, esos punteros de heap viven por encima de 4 GB y
                    // los ints quedan bajo 4 GB (o sign-extendidos como
                    // 0xFFFF...). Heurística: solo decodificamos como objeto
                    // cuando retval "parece" puntero de heap.
                    let asBig = null;
                    try {
                        // uint64() de frida-gum parsea "0x..." directamente.
                        asBig = uint64(retval.toString());
                    } catch (convError) {
                        asBig = null;
                    }
                    let looksObject = false;
                    if (asBig !== null) {
                        looksObject = asBig.compare(uint64('0x100000000')) >= 0 &&
                            asBig.compare(uint64('0xffff000000000000')) < 0;
                    }

                    let decoded = null;
                    if (looksObject) {
                        try {
                            const obj = new Il2Cpp.Object(retval);
                            const s = obj.method('ToString').invoke();
                            if (s !== null && s !== undefined) {
                                decoded = s.toString();
                            }
                        } catch (error) {
                            // No era un objeto manejable: usamos el valor crudo.
                        }
                    }
                    try {
                        const values = {};
                        values['return'] = decoded !== null
                            ? decoded
                            : readScalar(retval, config.returnType || 'int32');
                        if (decoded !== null) {
                            values['raw_pointer'] = retval.toString();
                        }
                        emitObservation(
                            subject, 'return', values, 'managed_function');
                        logInfo('onLeave: ' + JSON.stringify(values));
                    } catch (error) {
                        logError('No se pudo leer el retorno IL2CPP: ' + error.message);
                    }
                },
            });

            logInfo('Hook IL2CPP activo.');
        } catch (error) {
            logError('No se pudo localizar el método IL2CPP: ' + error.message);
        }
    });
}

try {
    emitDiagnosticProfile();
} catch (error) {
    logError('No se pudo detectar el perfil del proceso: ' + error.message);
}

try {
    if (CONFIG.mode === 'native') {
        attachNativeHook();
    } else if (CONFIG.mode === 'il2cpp') {
        attachIl2CppHook();
    } else {
        throw new Error('CONFIG.mode debe ser "native" o "il2cpp".');
    }
} catch (error) {
    logError(error.message);
}
