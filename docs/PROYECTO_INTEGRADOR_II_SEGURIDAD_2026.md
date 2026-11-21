# UniTrack — Proyecto Integrador II
## Seguridad preventiva universitaria, credenciales digitales y control de accesos
**Actualización técnica:** 21 de noviembre de 2026  
**Repositorio fuente:** [Peyman-mxli/unitrack](https://github.com/Peyman-mxli/unitrack)  
**Alcance:** prototipo académico; no constituye implantación oficial de la UPBC.

> Esta documentación se preparó contrastando archivos ejecutables Python, plantillas HTML, JavaScript y pruebas de la rama `main`; no se basa exclusivamente en descripciones antiguas del README. La existencia de una función en el código **no demuestra** que todos sus escenarios estén aprobados en el despliegue local o físico.

## 1. Problema y razón de la propuesta
Una comunidad universitaria necesita confirmar quién solicita ingresar y conservar registros fiables de entradas y salidas. La ausencia de un procedimiento uniforme podría facilitar accesos no autorizados y dificultar investigar incidentes. Las preocupaciones por amenazas graves, incluidas las que involucran armas, justifican medidas preventivas; **no se afirma que se haya verificado un incidente específico dentro de la UPBC**.

Otro problema operativo es la demora que puede existir entre el alta institucional y la entrega de la tarjeta física. UniTrack permite entregar una **credencial digital QR tras un registro validado** a estudiantes, docentes y personal, que puede imprimirse y utilizarse en un puesto de acceso autorizado.

**Límite importante:** el QR no detecta armas, no abre ni bloquea puertas por sí solo y no reemplaza a vigilantes, controles perimetrales, acreditación presencial y protocolos de emergencia.

## 2. Objetivo
Fortalecer la seguridad preventiva mediante verificación digital de usuarios autorizados, emisión rápida de credenciales firmadas, historial de entrada/salida, pases temporales a visitantes, avisos institucionales y soporte a usuarios.

## 3. Arquitectura: cliente y servidor
- **Cliente (navegador):** muestra el formulario de registro, tarjeta, camera QR, avisos, reportes e historial. HTML da estructura, CSS apariencia y JavaScript comportamientos como la lectura QR.
- **Servidor (Flask/Python):** recibe solicitudes HTTP, verifica sesión y rol, comprueba firmas y autorizaciones y realiza cambios transaccionales en la base de datos mediante SQLAlchemy.
- **Ejemplo:** `app/static/js/qr-camera.js` interpreta el QR y envía el formulario; rutas Flask y servicios verifican permisos y credencial, registran Entrada o Salida y devuelven el resultado. Una pantalla visible no demuestra por sí sola que la escritura persistió.

## 4. Tecnologías y dónde están realmente usadas

| Tecnología | Uso concreto | Ejemplo del código |
|---|---|---|
| HTML | Estructura de registro, credencial y dashboard | `app/templates/auth_register.html`, `credential_card.html` |
| CSS | Colores, diseño adaptable, menús y tarjetas | Estilos en `app/templates/admin_base.html`, `public_landing.html` |
| JavaScript | Escaneo de cámara, envío del formulario, historial | `app/static/js/qr-camera.js`, `access-history-live.js` |
| Python | Lógica de negocio, seguridad y operaciones | `app/services/account_security_service.py` |
| Flask | Rutas HTTP, sesiones y autorización | `app/routes/auth_routes.py`, `admin_views.py` |
| SQLite | Almacenamiento local | `app/models/user_model.py` y configuración de la app |
| SQLAlchemy | Modelos y transacciones de datos | `app/services/validation_code_service.py` |
| Flask-Login | Sesiones autenticadas y rutas protegidas | `app/routes/admin_views.py`, `credential_views.py` |
| Werkzeug + scrypt | Hash seguro de contraseñas | `app/utils/security.py` |
| itsdangerous + HMAC / hashlib | Firmas y verificación de credenciales | `app/services/permanent_credential_service.py` |
| qrcode y Pillow | Imagen de QR y credencial imprimible | `app/routes/credential_views.py`, `credential_card.html` |
| cryptography + TOTP | Protección de secretos y MFA admin | `app/services/admin_mfa_service.py` |
| Git y GitHub | Versionado de código, no de datos privados | Rama `main` de este repositorio |

Nota: las plantillas dinámicas son un detalle del renderizado web; este inventario se concentra en las tecnologías solicitadas y sus usos específicos.

## 5. Registro de cuentas: sólo con validación administrativa
**Rutas y servicios:** `app/routes/admin_views.py`, `app/routes/auth_routes.py`, `app/services/validation_code_service.py`.

1. Administración verifica personalmente la identidad y pertenencia institucional del solicitante.
2. Un usuario con rol `administrativo` abre `/admin/validation-codes` y genera un código aleatorio de **8 caracteres**, asociado a un **rol** y una **fecha de expiración**.
3. La persona abre `/auth/register-page` y escribe nombre, apellido, usuario, email, teléfono, rol, contraseña y código.
4. Flask rechaza códigos ausentes, inexistentes, usados, revocados, caducados o de otro rol.
5. Tras validación exitosa se crea la cuenta y se consume el código **una sola vez** dentro de la transacción de registro.
6. El usuario inicia sesión y puede ver su tarjeta digital permanente e imprimible en `/credentials/card`.

**Importante:** poseer un código compartido no demuestra por sí mismo afiliación. La comprobación de identidad antes de entregarlo es indispensable para la seguridad.

## 6. Contraseñas, sesiones y protección de cuentas
**Código comprobado:**
- `app/utils/password_policy.py`: mínimo **8 caracteres** (`MIN_PASSWORD_LENGTH = 8`), máximo 1024 y rechazo de claves previsibles o que contengan identificadores. **Quince caracteres no son un mínimo obligatorio.**
- `app/utils/security.py`: `generate_password_hash(password, method="scrypt:32768:8:1")` y comprobación mediante `check_password_hash`.
- `app/services/account_security_service.py`: historial de hashes para impedir reutilizar la contraseña actual o las anteriores **registradas desde la instalación de esta función**.
- En el quinto intento consecutivo incorrecto, la cuenta se bloquea durante **5 minutos**. Se intenta enviar aviso al correo y un enlace de desbloqueo sujeto a confirmación; el SMTP debe configurarse y probarse en el entorno.
- `app/utils/session_security.py`: sesión vinculada al hash actual, invalidando sesiones anteriores al cambiar la contraseña.
- `app/services/admin_mfa_service.py`: segundo factor administrativo TOTP de 30 segundos y códigos de recuperación de un solo uso; hay que inscribir y probar la cuenta.

## 7. Credenciales QR y entradas/salidas
- La credencial permanente es estable entre actualizaciones de vista, está firmada y puede revocarse al aprobar una sustitución: `app/services/permanent_credential_service.py`.
- La cámara decodifica el QR y puede enviar automáticamente el formulario: `app/static/js/qr-camera.js`.
- El escaneo autorizado registra **Entrada** cuando no hay una visita abierta y **Salida** cuando corresponde cerrarla; se conservan eventos históricos por rol.
- Deben probarse por separado: cámara automática, código manual, segunda lectura deliberada, envío duplicado rápido, historial después de recarga y persistencia en la base de datos.
- Un enlace QR abierto pasivamente no equivale a un registro oficial de acceso.

## 8. Visitantes, avisos y soporte
- Visitantes: `app/routes/credential_views.py` y `app/services/visitor_access_service.py`. El administrador puede emitir pase con vigencia definida y revocarlo. Debe verificarse aceptación del pase válido y rechazo del vencido.
- Avisos: solamente administración publica desde `/admin/send-notices` con audiencia `all` o por rol; los destinatarios reciben bandeja y marca de leído. Ejemplos: suspensión de actividades o eventos con fecha y hora. Código: `app/services/university_notice_service.py`.
- Reportes: un usuario autenticado puede enviar error, soporte, consulta o sugerencia desde `/credentials/report`. Administración responde mediante conversación privada del reporte y puede cerrarla. Código: `app/services/support_chat_service.py`. Es mensajería de soporte en la aplicación, **no garantiza respuesta instantánea**.

## 9. Plan de aceptación — evidencias solicitadas una por una
Los **22 casos** se documentan con resultado esperado, observado, fecha y captura. Estado de la versión documental: PF-01, PF-02, PF-03, PF-04 y PF-06 tienen **PASS visual** sustentado por capturas previas; PF-05 está **Parcial**; el resto sigue **Pendiente de evidencia de ejecución**. Este estado no implica ausencia del código.

| Caso | Escenario / evidencia a obtener |
|---|---|
| PF-01 | Página pública visible |
| PF-02 | Dashboard con métricas |
| PF-03 | Salida por QR |
| PF-04 | Historial con movimientos |
| PF-05 | Imprimir o guardar credencial de prueba como PDF |
| PF-06 | Solicitud QR aprobada |
| PF-07 | QR anterior rechazado tras sustitución |
| PF-08 | Pase de visitante realmente emitido |
| PF-09 | Pase caducado rechazado |
| PF-10 | Código alternativo registra movimiento correcto |
| PF-11 | Aviso enviado y recibido por audiencia autorizada |
| PF-12 | Reporte, respuesta y conversación privada |
| PF-13 | Usuario sin privilegios no puede entrar a ruta admin |
| PF-14 | Movimiento permanece después de recarga y en la BD |
| PF-15 | Escaneo duplicado rápido no crea salida accidental |
| PF-16 | Registro sin código / código erróneo / rol distinto rechazado |
| PF-17 | Código válido crea cuenta y no se puede reutilizar |
| PF-18 | Contraseña de 7 rechazada; de 8 válida si cumple política |
| PF-19 | Contraseña ya utilizada rechazada en cambio |
| PF-20 | Cinco intentos erróneos generan bloqueo de 5 minutos |
| PF-21 | Segundo factor admin TOTP probado |
| PF-22 | Cámara detecta automáticamente y registra entrada/salida |

El repositorio contiene `tests/test_unitrack.py` con pruebas automatizadas relevantes para los mecanismos anteriores (registro, QR, bloqueo, MFA, visitantes, chat y avisos). **La presencia de tests en GitHub no prueba su ejecución exitosa en el entorno actual.**

**Privacidad en capturas:** usar cuentas de demostración y no publicar contraseñas, QR activos, códigos de validación, enlaces de desbloqueo ni tokens. Para cada caso, registrar fecha/hora, rol, pasos, resultado esperado y real.

## 10. Próximo paso documentado
Empezar con **PF-05**: abrir Mi Credencial de un usuario de prueba, pulsar Imprimir / Guardar como PDF, seleccionar el destino PDF y capturar la pantalla sin revelar un QR activo. Después continuar con PF-07 y los demás casos pendientes **de uno en uno**, sin marcar PASS antes de reproducirlos.

---
**Nota de despliegue:** GitHub distribuye código; no sincroniza automáticamente bases SQLite locales, fotografías o secretos entre laptops. Para uso institucional real hacen falta verificación organizacional, operadores, barreras físicas, infraestructura persistente, privacidad y auditorías de seguridad.
