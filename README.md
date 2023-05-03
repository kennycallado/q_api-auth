# q_api-base

## Init a repo

### Extender plantilla

Acceder al repositorio en github y pulsar **Use this template**, **Create a new repository**. Una vez creado el repositorio puedes clonarlo localmente y seguir los siguientes pasos:

1. 
   ``` bash
   git checkout -b base
   ```
1. 
   ``` bash
   git remote add base git@github.com:kennycallado/q_api-base.git
   ```
1. 
   ``` bash
   git branch --set-upstream-to=base/main
   ```
1. 
   ``` bash
   git pull
   ```

   ``` bash
   git pull --allow-unrelated-histories
   ```

<!-- quizá mejor si no mantiene la rama
1. 
   ``` bash
   git checkout main
   ```
1. 
   ``` bash
   git push origin base
   ```
-->

### Adaptar proyecto

Algunos ficheros deben ser revisados y actualizados para cada proyecto derivado de base. En general están listados en la siguiente lista.

#### Raíz del proyecto

- [ ] .env
  - Dirección de la base de datos
- [ ] Cargo.toml
  - Nombre del paquete
  - Revisar dependencias
- [ ] Containerfile
  - Nombre del paquete desde Cargo.toml
- [ ] compose.yaml
  - Variables de entorno
  - Servicios extra
- [ ] Rocket.toml
  - Parámetros de configuración del proyecto
  - secret_key = `openssl rand -base64 32`

#### Directorio src

- [ ] Tests

#### Migraciones

Cada api tiene sus propias migraciones localizadas en el directorio `src/database/migrations`

#### Modules

Directorio principal de trabajo de cada api. Contendrá un módulo por cada entidad con la que trabaje la api y administrará sus rustas.

#### Module

Cada módulo deberá contener, `model.rs` y `controller.rs`. En caso de ser necesario el controlador puede ayudarse de un directorio `handlers` y el modelo puede tener un repositorio dentro del directorio `services`.

El directorio de servicios del módulo también puede contener por ejemplo, `helpers` para el controlador o implementación de `claims` para entidad user.

## Update a repo


## TODO:

- [ ] Something
