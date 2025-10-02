# Manual

## 📘 Manual (en Markdown) — Fundamentos de Node.js + Microservicios backend con Express y TypeScript, de 0 a producción

> Este libro práctico te guía paso a paso, desde instalar tus herramientas hasta publicar una aplicación de microservicios con autenticación, seguridad, mensajería asíncrona, observabilidad y CI/CD. Está escrito para quien empieza en Node/TypeScript, pero con el nivel de cuidado que exigiría un equipo senior.

***

### Índice

1. [Objetivos, alcance y prerequisitos](https://chatgpt.com/?temporary-chat=true#1-objetivos-alcance-y-prerequisitos)
2. [Instalación y entorno de desarrollo](https://chatgpt.com/?temporary-chat=true#2-instalaci%C3%B3n-y-entorno-de-desarrollo)
3. [Fundamentos esenciales de Node.js y TypeScript](https://chatgpt.com/?temporary-chat=true#3-fundamentos-esenciales-de-nodejs-y-typescript)
4. [Arquitectura de referencia de microservicios](https://chatgpt.com/?temporary-chat=true#4-arquitectura-de-referencia-de-microservicios)
5. [Estructura de monorepo con pnpm workspaces](https://chatgpt.com/?temporary-chat=true#5-estructura-de-monorepo-con-pnpm-workspaces)
6. [Paquete compartido “common”: Tipos, errores, middlewares](https://chatgpt.com/?temporary-chat=true#6-paquete-compartido-common-tipos-errores-middlewares)
7. [Plantilla de servicio Express + TS](https://chatgpt.com/?temporary-chat=true#7-plantilla-de-servicio-express--ts)
8. [Persistencia con PostgreSQL y Prisma por servicio](https://chatgpt.com/?temporary-chat=true#8-persistencia-con-postgresql-y-prisma-por-servicio)
9. [Mensajería asíncrona con NATS](https://chatgpt.com/?temporary-chat=true#9-mensajer%C3%ADa-as%C3%ADncrona-con-nats)
10. [Servicio de Autenticación (Auth)](https://chatgpt.com/?temporary-chat=true#10-servicio-de-autenticaci%C3%B3n-auth)
11. [API Gateway (BFF) con Express](https://chatgpt.com/?temporary-chat=true#11-api-gateway-bff-con-express)
12. [Servicio de Catálogo (Products)](https://chatgpt.com/?temporary-chat=true#12-servicio-de-cat%C3%A1logo-products)
13. [Servicio de Pedidos (Orders) + Saga/Choreography](https://chatgpt.com/?temporary-chat=true#13-servicio-de-pedidos-orders--sagachoreography)
14. [Servicio de Pagos (Payments) — simulación de proveedor](https://chatgpt.com/?temporary-chat=true#14-servicio-de-pagos-payments--simulaci%C3%B3n-de-proveedor)
15. [Validación, seguridad y hardening](https://chatgpt.com/?temporary-chat=true#15-validaci%C3%B3n-seguridad-y-hardening)
16. [Testing: unitario, integración, contrato y e2e](https://chatgpt.com/?temporary-chat=true#16-testing-unitario-integraci%C3%B3n-contrato-y-e2e)
17. [Observabilidad: logs, métricas y trazas](https://chatgpt.com/?temporary-chat=true#17-observabilidad-logs-m%C3%A9tricas-y-trazas)
18. [Docker, Docker Compose y migraciones](https://chatgpt.com/?temporary-chat=true#18-docker-docker-compose-y-migraciones)
19. [CI/CD con GitHub Actions](https://chatgpt.com/?temporary-chat=true#19-cicd-con-github-actions)
20. [Despliegue en Fly.io (o Render/Railway) con dominio y TLS](https://chatgpt.com/?temporary-chat=true#20-despliegue-en-flyio-o-renderrailway-con-dominio-y-tls)
21. [Operación: runbooks, escalado y troubleshooting](https://chatgpt.com/?temporary-chat=true#21-operaci%C3%B3n-runbooks-escalado-y-troubleshooting)
22. [Apéndices: archivos de configuración completos](https://chatgpt.com/?temporary-chat=true#22-ap%C3%A9ndices-archivos-de-configuraci%C3%B3n-completos)

***

### 1) Objetivos, alcance y prerequisitos

**Objetivos**

* Entender **Node.js + TypeScript** aplicados a backend.
* Diseñar y construir una **arquitectura de microservicios** basada en **Express**.
* Implementar **autenticación** (JWT + Refresh Tokens) y **autorización** (RBAC).
* Integrar **PostgreSQL + Prisma**, **Redis** (sesiones/caché) y **NATS** (eventos).
* Añadir **validación**, **seguridad**, **observabilidad**, **tests** y **CI/CD**.
* Publicar una app real operativa en la nube.

**Qué construiremos (dominio de ejemplo)**

* **auth**: registro, login, refresh, roles, verificación de email (simulada).
* **catalog**: CRUD de productos.
* **orders**: creación de pedidos, saga con **payments**.
* **payments**: pasarela simulada y emisión de eventos.
* **gateway**: BFF/API Gateway que orquesta y expone el frontal público.

**Prerrequisitos técnicos**

* Conocimientos básicos de JS/TS.
* Git, Docker.
* **Node.js 20+** y **pnpm**.

***

### 2) Instalación y entorno de desarrollo

```bash
# Node 20 LTS recomendado
node -v

# Instala pnpm
npm i -g pnpm

# Utilidades
brew install jq mkcert # macOS (opcional)
# Linux: usa el gestor de paquetes equivalente
```

Extensiones VS Code recomendadas:

* **ESLint**, **Prettier**, **Prisma**, **DotENV**, **Docker**, **Thunder Client/REST Client**.

***

### 3) Fundamentos esenciales de Node.js y TypeScript

**Event Loop**: modelo no bloqueante; usa APIs async (promises/async-await).\
**Módulos**: ES Modules nativos (type: "module") o CommonJS; elegiremos **ESM**.\
**TypeScript**: tipado estático, `tsconfig.json`, `tsc --noEmit` en CI para typecheck rápido.\
**Buenas prácticas**:

* **Principio KISS** y **SRP**: funciones pequeñas, separación de capas (router → controller → service → repository).
* **Errores** con clases personalizadas y middleware de error central.
* **Configuración** por **variables de entorno**; nunca credenciales en el repo.

***

### 4) Arquitectura de referencia de microservicios

**Estilo**: microservicios pequeños con independencia de despliegue.\
**Comunicación**:

* **Sincrónica**: REST entre Gateway y servicios.
* **Asíncrona**: **eventos** con **NATS** (pub/sub).\
  **Datos**: **base de datos por servicio** (evita acoplamiento).\
  **Resiliencia**: timeouts, retries, circuit breaker (a nivel gateway o librería).\
  **Observabilidad**: logs correlacionados (request-id), OpenTelemetry, métricas Prometheus.

Diagrama (texto):

```
[Client] → [Gateway/BFF] → REST → [auth]
                         → REST → [catalog]
                         → REST → [orders] → REST → [payments]

NATS (event bus):
  auth→UserCreated, payments→PaymentAuthorized/Failed, orders→OrderCreated/Completed
```

***

### 5) Estructura de monorepo con pnpm workspaces

```
/acme-shop/
  package.json
  pnpm-workspace.yaml
  tsconfig.base.json
  docker-compose.yml
  .github/workflows/
  /packages/
    /common/         # tipos y utilidades compartidas
  /services/
    /auth/
    /catalog/
    /orders/
    /payments/
    /gateway/
```

**pnpm-workspace.yaml**

```yaml
packages:
  - "packages/*"
  - "services/*"
```

**package.json (raíz)**

```json
{
  "name": "acme-shop",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "pnpm -r --filter './services/*' run build",
    "dev": "pnpm -r --parallel --filter './services/*' run dev",
    "lint": "eslint .",
    "typecheck": "tsc -b --pretty false",
    "test": "pnpm -r test"
  },
  "devDependencies": {
    "typescript": "^5.6.0",
    "eslint": "^9.0.0",
    "@typescript-eslint/eslint-plugin": "^8.0.0",
    "@typescript-eslint/parser": "^8.0.0",
    "prettier": "^3.3.0",
    "ts-node": "^10.9.2"
  }
}
```

**tsconfig.base.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "baseUrl": ".",
    "paths": {
      "@acme/common/*": ["packages/common/src/*"]
    }
  }
}
```

***

### 6) Paquete compartido `common`: Tipos, errores, middlewares

**packages/common/package.json**

```json
{
  "name": "@acme/common",
  "version": "0.1.0",
  "type": "module",
  "main": "src/index.ts",
  "dependencies": {
    "zod": "^3.23.8",
    "http-errors": "^2.0.0",
    "pino": "^9.0.0",
    "pino-http": "^10.0.0",
    "cls-hooked": "^4.2.2",
    "ulid": "^2.3.0"
  }
}
```

**packages/common/src/errors.ts**

```ts
import createError from 'http-errors';

export const errors = {
  BadRequest: createError.BadRequest,
  Unauthorized: createError.Unauthorized,
  Forbidden: createError.Forbidden,
  NotFound: createError.NotFound,
  Conflict: createError.Conflict
};

export type AppError = createError.HttpError;
```

**packages/common/src/request-id.ts**

```ts
import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

export function requestId() {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.headers['x-request-id']?.toString() ?? randomUUID();
    (req as any).requestId = id;
    res.setHeader('x-request-id', id);
    next();
  };
}
```

**packages/common/src/logger.ts**

```ts
import pino from 'pino';
import pinoHttp from 'pino-http';

export const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' });

export const httpLogger = pinoHttp({
  logger,
  genReqId: req => (req as any).requestId || undefined,
  customProps: req => ({ svc: process.env.SVC_NAME || 'unknown' })
});
```

**packages/common/src/validate.ts**

```ts
import type { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';
import { errors } from './errors.js';

export const validate =
  (schema: ZodSchema, where: 'body' | 'params' | 'query' = 'body') =>
  (req: Request, _res: Response, next: NextFunction) => {
    const result = schema.safeParse((req as any)[where]);
    if (!result.success) {
      return next(new errors.BadRequest(result.error.issues.map(i => i.message).join('; ')));
    }
    (req as any)[where] = result.data;
    next();
  };
```

**packages/common/src/index.ts**

```ts
export * from './errors.js';
export * from './request-id.js';
export * from './logger.js';
export * from './validate.js';
```

***

### 7) Plantilla de servicio Express + TS

Estructura mínima por servicio:

```
/services/<svc>/
  package.json
  tsconfig.json
  src/
    app.ts
    index.ts
    routes/
    controllers/
    services/
    repositories/
    middlewares/
```

**package.json (servicio base)**

```json
{
  "name": "@acme/auth",            // cambia por servicio
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc -p tsconfig.json",
    "start": "node dist/index.js",
    "test": "vitest run"
  },
  "dependencies": {
    "express": "^4.19.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "dotenv": "^16.4.5",
    "@acme/common": "workspace:*"
  },
  "devDependencies": {
    "tsx": "^4.19.0",
    "typescript": "^5.6.0",
    "vitest": "^2.0.0",
    "supertest": "^7.0.0"
  }
}
```

**tsconfig.json**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "dist",
    "noEmit": false
  },
  "include": ["src"]
}
```

**src/app.ts**

```ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { httpLogger, requestId } from '@acme/common';

export function buildApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(requestId());
  app.use(httpLogger);
  app.use(helmet());
  app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') ?? '*', credentials: true }));
  app.use(express.json({ limit: '1mb' }));

  app.use(rateLimit({ windowMs: 60_000, max: 100 }));

  // health
  app.get('/health', (_req, res) => res.json({ ok: true, svc: process.env.SVC_NAME }));

  return app;
}
```

**src/index.ts**

```ts
import { buildApp } from './app.js';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const app = buildApp();

app.listen(PORT, () => {
  console.log(`[${process.env.SVC_NAME}] listening on :${PORT}`);
});
```

***

### 8) Persistencia con PostgreSQL y Prisma por servicio

Cada servicio gestiona su **propia** base de datos (aislamiento lógico).

#### Instalación Prisma (por servicio)

```bash
pnpm add prisma @prisma/client -w              # en raíz si quieres CLI compartida
cd services/auth
pnpm add @prisma/client
pnpm dlx prisma init --datasource-provider postgresql
```

**.env (del servicio)**

```
DATABASE_URL="postgresql://user:pass@postgres-auth:5432/auth"
```

**schema.prisma (auth)**

```prisma
datasource db { provider = "postgresql" url = env("DATABASE_URL") }
generator client { provider = "prisma-client-js" }

model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  name      String
  role      Role     @default(USER)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  // opcional: emailVerifiedAt DateTime?
}

enum Role {
  USER
  ADMIN
}
```

Comandos:

```bash
pnpm dlx prisma migrate dev -n init
pnpm dlx prisma generate
```

***

### 9) Mensajería asíncrona con NATS

Usaremos **NATS JetStream** simple para pub/sub de eventos de dominio.

**Dependencias comunes por servicio que publique/consuma**:

```bash
pnpm add nats
```

**Patrones**

* **Evento inmutable** con `type`, `version`, `data`, `meta`.
* Nombres de subjects: `svc.event` (p.ej., `payments.payment_authorized.v1`).
* **Idempotencia**: consumidores registran `eventId` procesados.

**Ejemplo publisher (payments)**

```ts
import { connect, StringCodec } from 'nats';
const sc = StringCodec();

export async function publishPaymentAuthorized(evt: {
  eventId: string; orderId: string; amount: number; userId: string;
}) {
  const nc = await connect({ servers: process.env.NATS_URL || 'nats://nats:4222' });
  const payload = {
    type: 'payment.authorized',
    version: 1,
    data: evt,
    meta: { occurredAt: new Date().toISOString(), source: 'payments' }
  };
  await nc.publish('payments.payment_authorized.v1', sc.encode(JSON.stringify(payload)));
  await nc.drain();
}
```

**Ejemplo subscriber (orders)**

```ts
import { connect, StringCodec } from 'nats';
const sc = StringCodec();

export async function listenPaymentEvents(onAuthorized: (data: any) => Promise<void>) {
  const nc = await connect({ servers: process.env.NATS_URL || 'nats://nats:4222' });
  const sub = nc.subscribe('payments.payment_authorized.v1');
  (async () => {
    for await (const m of sub) {
      const evt = JSON.parse(sc.decode(m.data));
      await onAuthorized(evt.data);
    }
  })();
}
```

***

### 10) Servicio de Autenticación (Auth)

**Endpoints**

* `POST /auth/register` — email, password, name.
* `POST /auth/login` — email, password → `accessToken` (JWT, 15 min) y **refresh token** en cookie HttpOnly (7 días).
* `POST /auth/refresh` — usa cookie.
* `POST /auth/logout` — invalida refresh.
* `GET /auth/me` — datos del usuario.
* (Opcional) `POST /auth/verify-email` simulado.

**Dependencias**

```bash
pnpm add argon2 jsonwebtoken cookie-parser
pnpm add @prisma/client
```

**src/services/jwt.ts**

```ts
import jwt from 'jsonwebtoken';

const ACCESS_TTL = '15m';
const REFRESH_TTL = '7d';

export function signAccess(payload: object) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, { expiresIn: ACCESS_TTL });
}
export function signRefresh(payload: object) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, { expiresIn: REFRESH_TTL });
}
export function verifyAccess(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as any;
}
export function verifyRefresh(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as any;
}
```

**src/controllers/auth.controller.ts**

```ts
import { errors } from '@acme/common';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import type { Request, Response } from 'express';
import { signAccess, signRefresh, verifyRefresh } from '../services/jwt.js';

const prisma = new PrismaClient();

export async function register(req: Request, res: Response) {
  const { email, password, name } = req.body;
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new errors.Conflict('Email already registered');
  const hash = await argon2.hash(password);
  const user = await prisma.user.create({ data: { email, password: hash, name } });
  res.status(201).json({ id: user.id, email: user.email, name: user.name, role: user.role });
}

export async function login(req: Request, res: Response) {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await argon2.verify(user.password, password))) {
    throw new errors.Unauthorized('Invalid credentials');
  }
  const accessToken = signAccess({ sub: user.id, role: user.role });
  const refreshToken = signRefresh({ sub: user.id, tokenUse: 'refresh' });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true, secure: true, sameSite: 'strict', path: '/auth/refresh', maxAge: 7 * 24 * 3600 * 1000
  });
  res.json({ accessToken });
}

export async function refresh(req: Request, res: Response) {
  const token = req.cookies?.refresh_token;
  if (!token) throw new errors.Unauthorized('Missing refresh token');
  const payload = verifyRefresh(token);
  const accessToken = signAccess({ sub: payload.sub, role: payload.role });
  res.json({ accessToken });
}

export async function me(req: Request, res: Response) {
  res.json({ userId: (req as any).userId, role: (req as any).role });
}
```

**Middleware `requireAuth`**

```ts
import { errors } from '@acme/common';
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return next(new errors.Unauthorized());
  try {
    const payload = jwt.verify(h.slice(7), process.env.JWT_ACCESS_SECRET!) as any;
    (req as any).userId = payload.sub;
    (req as any).role = payload.role;
    next();
  } catch {
    next(new errors.Unauthorized());
  }
}

export function requireRole(role: 'ADMIN' | 'USER') {
  return (req: Request, _res: Response, next: NextFunction) => {
    if ((req as any).role !== role) return next(new errors.Forbidden());
    next();
  };
}
```

**Rutas**

```ts
import { Router } from 'express';
import cookieParser from 'cookie-parser';
import { validate } from '@acme/common';
import { z } from 'zod';
import { register, login, refresh, me } from '../controllers/auth.controller.js';
import { requireAuth } from '../middlewares/require-auth.js';

export const router = Router();
router.use(cookieParser());

router.post('/auth/register', validate(z.object({
  email: z.string().email(), password: z.string().min(8), name: z.string().min(1)
})), register);

router.post('/auth/login', validate(z.object({
  email: z.string().email(), password: z.string().min(8)
})), login);

router.post('/auth/refresh', refresh);
router.get('/auth/me', requireAuth, me);
```

Integra `router` en `app.ts` del servicio `auth`.

***

### 11) API Gateway (BFF) con Express

Responsabilidades:

* **Terminar CORS**, rate-limit, headers de seguridad.
* **Autenticación**: validar JWT y propagar `x-user-id` y `x-user-role`.
* **Proxy** a servicios (con timeouts y circuit breaker).
* **OpenAPI** (Swagger) publicado en `/docs`.

**Dependencias**

```bash
pnpm add http-proxy-middleware swagger-ui-express yamljs
```

**src/gateway/proxy.ts**

```ts
import { createProxyMiddleware } from 'http-proxy-middleware';

export function mkProxy(target: string, pathRewrite?: Record<string,string>) {
  return createProxyMiddleware({
    target, changeOrigin: true,
    pathRewrite, logLevel: 'warn',
    timeout: 5000, proxyTimeout: 5000
  });
}
```

**src/gateway/auth-propagation.ts**

```ts
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export function authenticate(req: Request, _res: Response, next: NextFunction) {
  const h = req.headers.authorization;
  if (h?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(h.slice(7), process.env.JWT_ACCESS_SECRET!) as any;
      req.headers['x-user-id'] = payload.sub;
      req.headers['x-user-role'] = payload.role;
    } catch (e) {
      // sigue como anónimo
    }
  }
  next();
}
```

**src/app.ts (gateway)** — ejemplo de montaje

```ts
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import { mkProxy } from './proxy.js';
import { authenticate } from './auth-propagation.js';

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') ?? '*', credentials: true }));
app.use(express.json());

app.use(authenticate);

// Rutas públicas del gateway
app.get('/health', (_req,res)=>res.json({ok:true,svc:'gateway'}));

// Documentación (carga YAML generado/estático)
const doc = YAML.load('./openapi.yaml');
app.use('/docs', swaggerUi.serve, swaggerUi.setup(doc));

// Proxys
app.use('/auth', mkProxy(process.env.AUTH_URL!, { '^/auth': '' }));
app.use('/catalog', mkProxy(process.env.CATALOG_URL!, { '^/catalog': '' }));
app.use('/orders', mkProxy(process.env.ORDERS_URL!, { '^/orders': '' }));
app.use('/payments', mkProxy(process.env.PAYMENTS_URL!, { '^/payments': '' }));

export default app;
```

***

### 12) Servicio de Catálogo (Products)

**schema.prisma (catalog)**

```prisma
model Product {
  id          String   @id @default(uuid())
  name        String
  description String
  priceCents  Int
  stock       Int      @default(0)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}
```

**Rutas**

* `GET /products` (paginado `?limit=&cursor=`)
* `POST /products` (ADMIN)
* `GET /products/:id`
* `PUT /products/:id` (ADMIN)
* `DELETE /products/:id` (ADMIN)

**Ejemplo controller `create`**

```ts
import { PrismaClient } from '@prisma/client';
import { errors } from '@acme/common';
import type { Request, Response } from 'express';

const prisma = new PrismaClient();

export async function createProduct(req: Request, res: Response) {
  const role = (req as any).role;
  if (role !== 'ADMIN') throw new errors.Forbidden();
  const p = await prisma.product.create({ data: req.body });
  res.status(201).json(p);
}
```

***

### 13) Servicio de Pedidos (Orders) + Saga/Choreography

**schema.prisma (orders)**

```prisma
model Order {
  id          String   @id @default(uuid())
  userId      String
  status      OrderStatus @default(PENDING)
  totalCents  Int
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  // opcional: items como JSONB para simplificar el ejemplo
  items       Json
}

enum OrderStatus {
  PENDING
  PAID
  FAILED
  CANCELLED
}
```

**Flujo**

1. `POST /orders` → create `PENDING`, calcula `totalCents`.
2. Emite REST a `payments` o publica evento `OrderCreated`.
3. `payments` autoriza y **publica evento** `payment.authorized`.
4. `orders` escucha evento y marca `PAID` (o `FAILED`).

**Rutas**

* `POST /orders` (requiere auth)
* `GET /orders/:id` (dueño o ADMIN)
* `GET /orders` (del usuario autenticado)

**Ejemplo creación y disparo de pago (sincronía simple)**

```ts
import axios from 'axios';
import { PrismaClient } from '@prisma/client';
import { errors } from '@acme/common';

const prisma = new PrismaClient();

export async function createOrder(req, res) {
  const userId = (req as any).userId;
  if (!userId) throw new errors.Unauthorized();

  const { items } = req.body; // [{productId, qty, priceCents}]
  const totalCents = items.reduce((s: number, it: any)=> s + it.qty * it.priceCents, 0);

  const order = await prisma.order.create({
    data: { userId, totalCents, items, status: 'PENDING' }
  });

  try {
    const r = await axios.post(process.env.PAYMENTS_URL + '/charge', {
      orderId: order.id, userId, amount: totalCents
    }, { timeout: 4000 });
    if (r.data.status === 'AUTHORIZED') {
      await prisma.order.update({ where: { id: order.id }, data: { status: 'PAID' } });
    } else {
      await prisma.order.update({ where: { id: order.id }, data: { status: 'FAILED' } });
    }
  } catch {
    // degradación: queda PENDING o FAILED por timeout
  }

  res.status(201).json(order);
}
```

**Versión event-driven (recomendada)**: en vez de llamar a `payments` por REST, publica “OrderCreated” y espera evento “payment.authorized/failed”. (Código análogo al de NATS en la sección 9).

***

### 14) Servicio de Pagos (Payments) — simulación de proveedor

**Rutas**

* `POST /charge` → simula autorización (80% éxito), emite evento.
* `POST /refund` (opcional).

**Controller**

```ts
import { publishPaymentAuthorized } from '../events/publishers.js';

export async function charge(req, res) {
  const { orderId, userId, amount } = req.body;
  const ok = Math.random() < 0.8;
  if (ok) {
    await publishPaymentAuthorized({ eventId: crypto.randomUUID(), orderId, amount, userId });
    return res.json({ status: 'AUTHORIZED' });
  }
  // emitir evento failed (similar)
  return res.status(402).json({ status: 'DECLINED' });
}
```

***

### 15) Validación, seguridad y hardening

**Validación**

* Zod/Joi en **entrada** (body/params/query).
* Sanitización (limit de JSON, strings con longitud).

**Autenticación y autorización**

* **JWT** corto (15m) + **Refresh** en cookie HttpOnly.
* **RBAC** con claim `role` en access token.
* Endpoints admin protegidos (`requireRole('ADMIN')`).

**Cabeceras y políticas**

* `helmet()` activa políticas seguras (CSP si sirves HTML).
* `cors()` restringe orígenes.
* **Rate limit** por IP/usuario.

**Almacenamiento de secretos**

* `.env` local (nunca en git).
* En producción: **secrets manager** (Fly, Render, Railway, AWS SSM).

**OWASP Top 10 (resumen aplicable)**

* Inyección: usa Prisma/parametrización, valida entrada.
* Auth rota: fuerza passwords fuertes (argon2), lockout tras N intentos (opcional, con Redis).
* Exposición de datos: evita stack traces al cliente, no filtraciones en logs.
* SSRF/CSRF: no hacemos SSRF; para CSRF usa **SameSite=strict** y verifica origen si usas cookies para access token (aquí solo refresh).

**Logs y privacidad**

* Nunca loguear contraseñas, tokens o cookies.
* PII mínima, con enmascaramiento si necesario.

***

### 16) Testing: unitario, integración, contrato y e2e

**Stack**: Vitest + Supertest.

**Unitarios**

* Servicios y utilidades puras (sin red/DB).

**Integración**

* Controllers con **Supertest** montando `app` y una DB **temporal** (prisma con `DATABASE_URL` a un contenedor de Postgres de test).

**Contratos** (opcional pero recomendado)

* Pact o Schemas compartidos (Zod) versionados entre servicios y gateway.

**E2E**

* `docker-compose -f docker-compose.e2e.yml up -d`
* Ejecuta tests contra el **gateway** y valida flujos reales (registro → login → crear order → pago).

Ejemplo de test integración (auth login):

```ts
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { buildApp } from '../src/app.js';

describe('auth login', () => {
  it('rejects invalid credentials', async () => {
    const app = buildApp();
    const r = await request(app).post('/auth/login').send({ email: 'x@x.com', password: 'bad' });
    expect(r.status).toBe(401);
  });
});
```

***

### 17) Observabilidad: logs, métricas y trazas

**Logs estructurados** con **pino** (ya incluido).\
**Correlación** con `x-request-id` (propagado por gateway).\
**Métricas**: expón `/metrics` con `prom-client` (contadores de requests, latencias).\
**Trazas**: OpenTelemetry SDK (export a OTLP/Jaeger/Tempo si lo deseas).

Ejemplo de métricas básicas:

```bash
pnpm add prom-client
```

```ts
import client from 'prom-client';
const reqCounter = new client.Counter({ name: 'http_requests_total', help: 'total' });
// en middleware de cada request: reqCounter.inc();
```

***

### 18) Docker, Docker Compose y migraciones

**Dockerfile (base Node 20, por servicio)**

```dockerfile
FROM node:20-slim AS base
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@latest --activate
COPY . .
RUN pnpm install --frozen-lockfile

FROM base AS build
RUN pnpm -r --filter . run build

FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/dist ./dist
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@latest --activate && pnpm install --prod --frozen-lockfile
CMD ["node", "dist/index.js"]
```

**docker-compose.yml (desarrollo)**

```yaml
version: "3.9"
services:
  postgres-auth:
    image: postgres:16
    environment: [ POSTGRES_PASSWORD=pass, POSTGRES_USER=user, POSTGRES_DB=auth ]
    ports: ["5433:5432"]
  postgres-catalog:
    image: postgres:16
    environment: [ POSTGRES_PASSWORD=pass, POSTGRES_USER=user, POSTGRES_DB=catalog ]
  postgres-orders:
    image: postgres:16
    environment: [ POSTGRES_PASSWORD=pass, POSTGRES_USER=user, POSTGRES_DB=orders ]
  postgres-payments:
    image: postgres:16
    environment: [ POSTGRES_PASSWORD=pass, POSTGRES_USER=user, POSTGRES_DB=payments ]
  redis:
    image: redis:7
  nats:
    image: nats:2
    command: ["-js"]
    ports: ["4222:4222"]

  auth:
    build: ./services/auth
    environment:
      - SVC_NAME=auth
      - PORT=3001
      - DATABASE_URL=postgresql://user:pass@postgres-auth:5432/auth
      - JWT_ACCESS_SECRET=devaccess
      - JWT_REFRESH_SECRET=devrefresh
      - NATS_URL=nats://nats:4222
    depends_on: [postgres-auth, nats]
    ports: ["3001:3001"]

  catalog:
    build: ./services/catalog
    environment:
      - SVC_NAME=catalog
      - PORT=3002
      - DATABASE_URL=postgresql://user:pass@postgres-catalog:5432/catalo
      - NATS_URL=nats://nats:4222
    depends_on: [postgres-catalog, nats]
    ports: ["3002:3002"]

  orders:
    build: ./services/orders
    environment:
      - SVC_NAME=orders
      - PORT=3003
      - DATABASE_URL=postgresql://user:pass@postgres-orders:5432/orders
      - PAYMENTS_URL=http://payments:3004
      - NATS_URL=nats://nats:4222
    depends_on: [postgres-orders, payments, nats]
    ports: ["3003:3003"]

  payments:
    build: ./services/payments
    environment:
      - SVC_NAME=payments
      - PORT=3004
      - DATABASE_URL=postgresql://user:pass@postgres-payments:5432/payments
      - NATS_URL=nats://nats:4222
    depends_on: [postgres-payments, nats]
    ports: ["3004:3004"]

  gateway:
    build: ./services/gateway
    environment:
      - SVC_NAME=gateway
      - PORT=3000
      - AUTH_URL=http://auth:3001
      - CATALOG_URL=http://catalog:3002
      - ORDERS_URL=http://orders:3003
      - PAYMENTS_URL=http://payments:3004
      - JWT_ACCESS_SECRET=devaccess
    depends_on: [auth, catalog, orders, payments]
    ports: ["3000:3000"]
```

> **Migraciones:** ejecuta `prisma migrate deploy` en el startup de cada servicio (o en CI). En dev: `pnpm dlx prisma migrate dev`.

***

### 19) CI/CD con GitHub Actions

**.github/workflows/ci.yml**

```yaml
name: ci
on:
  push: { branches: [main] }
  pull_request:
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20', cache: 'pnpm' }
      - run: corepack enable
      - run: corepack prepare pnpm@latest --activate
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck
      - run: pnpm test
```

**Build y push de imágenes (opcional)**

```yaml
  docker:
    needs: build-test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USER }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: ./services/gateway/Dockerfile
          push: true
          tags: ${{ secrets.DOCKERHUB_USER }}/acme-gateway:latest
```

***

### 20) Despliegue en Fly.io (o Render/Railway) con dominio y TLS

**Fly.io (idea general por servicio)**:

```bash
flyctl launch --name acme-gateway --dockerfile ./services/gateway/Dockerfile
flyctl secrets set JWT_ACCESS_SECRET=xxx JWT_REFRESH_SECRET=yyy
flyctl deploy
```

* Repite para `auth`, `catalog`, `orders`, `payments`, `nats`, `redis`, `postgres` (Fly tiene add-ons).
* Configura **orígenes** del CORS a tu dominio (ej. `https://app.tudominio.com`).

**Dominio y TLS**

* Apunta DNS (CNAME/AAAA) al host de Fly.
* Certificado gestionado automáticamente.

> Alternativas: Render/Railway con servicios separados y variables de entorno equivalentes.

***

### 21) Operación: runbooks, escalado y troubleshooting

**Runbook rápido**

* Health checks: `GET /health` de cada servicio.
* Logs: `kubectl logs` o `flyctl logs` / panel del proveedor.
* DB: verifica conexiones y migraciones aplicadas.
* NATS: ¿consumidores suscritos? ¿reintentos?

**Escalado**

* **Horizontal**: más réplicas de servicios **sin estado** (gateway, catalog, payments).
* **Bottleneck típicos**: DB (añade índices, pooling), nats (memoria), orders (transacciones).
* Caché con **Redis** para `GET /products`.

**Backup & DR**

* Snapshots de PostgreSQL (proveedor) y volúmenes.

***

### 22) Apéndices: archivos de configuración completos

#### A) `.env.example` (por servicio)

```
SVC_NAME=auth
PORT=3001
DATABASE_URL=postgresql://user:pass@localhost:5433/auth
JWT_ACCESS_SECRET=change-me
JWT_REFRESH_SECRET=change-me-too
CORS_ORIGIN=http://localhost:5173
NATS_URL=nats://localhost:4222
```

#### B) `.eslintrc.cjs`

```js
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended', 'prettier'],
  env: { node: true, es2022: true },
  ignorePatterns: ['dist', 'node_modules']
};
```

#### C) `openapi.yaml` (extracto)

```yaml
openapi: 3.0.3
info: { title: Acme Shop API, version: 0.1.0 }
servers: [{ url: https://api.tudominio.com }]
paths:
  /auth/register:
    post:
      summary: Register user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, password, name]
              properties:
                email: { type: string, format: email }
                password: { type: string, minLength: 8 }
                name: { type: string }
      responses:
        "201": { description: Created }
```

#### D) Scripts útiles

**Arranque de todo en dev**

```bash
docker compose up -d postgres-auth postgres-catalog postgres-orders postgres-payments nats redis
pnpm -r --filter './services/*' dev
```

**Migraciones**

```bash
# En cada servicio:
cd services/auth && pnpm dlx prisma migrate dev
```

**Seed de datos (catalog)**

```ts
// services/catalog/prisma/seed.ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
await prisma.product.createMany({
  data: [
    { name: 'Camiseta', description: '100% algodón', priceCents: 1999, stock: 50 },
    { name: 'Gorra', description: 'Unitalla', priceCents: 1299, stock: 100 }
  ]
});
process.exit(0);
```

***

### Checklist de implementación (paso a paso resumido)

1. **Clona** repositorio vacío y crea monorepo con `pnpm-workspace.yaml`.
2. **Crea** `packages/common` con middlewares (request-id, logger, validate).
3. **Scaffolding** de servicios `auth`, `catalog`, `orders`, `payments`, `gateway`.
4. **Configura Prisma** y DB por servicio; ejecuta **migraciones**.
5. Implementa **Auth** (registro/login/refresh/me) con **argon2** + **JWT**.
6. **Gateway** con proxy, CORS, rate limit, propagación de auth, `/docs`.
7. **Catalog** CRUD + validaciones y RBAC (ADMIN).
8. **Orders** + flujo de pago (REST) → luego **event-driven con NATS**.
9. **Payments** simulado, publica eventos.
10. Añade **tests** (unit, integración) y **observabilidad** básica.
11. **Dockeriza** servicios + Compose; scripts de migración.
12. **CI** en GitHub Actions (lint/typecheck/test) y **CD** (opcional).
13. **Despliega** en Fly/Render/Railway; configura variables y dominio.
14. Monitorea, itera y **documenta** en `openapi.yaml`.
