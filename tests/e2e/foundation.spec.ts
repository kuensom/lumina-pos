import { expect, test } from "@playwright/test";

const username = process.env.LUMINA_E2E_USERNAME;
const email = process.env.LUMINA_E2E_EMAIL;
const password = process.env.LUMINA_E2E_PASSWORD;

test.beforeEach(() => {
  expect(username).toBeTruthy();
  expect(email).toBeTruthy();
  expect(password).toBeTruthy();
});

test("authenticated dashboard is protected and visible after username login", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await signIn(page, username!);

  await expect(
    page.getByRole("heading", { name: "Lumina POS dashboard" }),
  ).toBeVisible();
  await expect(
    page.getByText("Your session and dashboard permission were verified"),
  ).toBeVisible();
});

test("email login creates a confidential HttpOnly cookie and logout revokes it", async ({
  page,
  context,
}) => {
  await page.goto("/login");
  await signIn(page, email!);

  const sessionCookie = (await context.cookies()).find((cookie) =>
    cookie.name.endsWith("next-auth.session-token"),
  );
  expect(sessionCookie).toBeTruthy();
  expect(sessionCookie!.httpOnly).toBe(true);
  expect(sessionCookie!.sameSite).toBe("Lax");
  expect(sessionCookie!.value).not.toContain(username!);
  expect(sessionCookie!.value).not.toContain(email!);
  expect(sessionCookie!.value).not.toContain(password!);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
});

test("login failures are generic", async ({ page }) => {
  await page.goto("/login");

  await expect(
    page.getByRole("heading", { name: "Sign in to Lumina POS" }),
  ).toBeVisible();
  await page.getByLabel("Username or email").fill(username!);
  await page.getByLabel("Password").fill("wrong password value");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByText("Unable to sign in with those credentials."),
  ).toBeVisible();
});

test("credentials callback rejects a missing CSRF token", async ({
  request,
}) => {
  const response = await request.post("/api/auth/callback/credentials", {
    form: { identifier: username!, password: password!, callbackUrl: "/" },
    maxRedirects: 0,
  });
  expect(response.status()).toBe(302);
  expect(response.headers().location).toContain("csrf=true");
});

test("health endpoint reports the service status", async ({ request }) => {
  const response = await request.get("/api/health");

  expect(response.ok()).toBe(true);
  await expect(response.json()).resolves.toEqual({
    status: "ok",
    service: "lumina-pos",
  });
});

async function signIn(
  page: import("@playwright/test").Page,
  identifier: string,
) {
  await page.getByLabel("Username or email").fill(identifier);
  await page.getByLabel("Password").fill(password!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
}
