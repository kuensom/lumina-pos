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

test("authentication endpoint rejects an oversized request body", async ({
  request,
}) => {
  const response = await request.post("/api/auth/callback/credentials", {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    data: `identifier=${"a".repeat(5000)}`,
  });
  expect(response.status()).toBe(413);
  await expect(response.json()).resolves.toEqual({
    error: "Authentication request rejected.",
  });
});

test("health endpoint reports the service status", async ({ request }) => {
  const response = await request.get("/api/health");

  expect(response.ok()).toBe(true);
  await expect(response.json()).resolves.toEqual({
    status: "ok",
    service: "lumina-pos",
  });
});

test("administrator can create an enrollment-ready staff account", async ({
  page,
}) => {
  const administratorUsername = process.env.LUMINA_E2E_ADMIN_USERNAME;
  const administratorPassword = process.env.LUMINA_E2E_ADMIN_PASSWORD;
  expect(administratorUsername).toBeTruthy();
  expect(administratorPassword).toBeTruthy();
  await page.goto("/login");
  await page.getByLabel("Username or email").fill(administratorUsername!);
  await page.getByLabel("Password").fill(administratorPassword!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
  await page.goto("/admin/staff/new");
  const username = `browser.staff.${Date.now()}`;
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Display name").fill("Browser Test Staff");
  await page.getByLabel("Cashier / Sales Staff").check();
  await page.getByRole("button", { name: "Create staff account" }).click();
  await expect(page.getByRole("status")).toContainText("Staff account created");
  await page.goto(`/admin/staff?query=${encodeURIComponent(username)}`);
  await expect(page.getByText(username)).toBeVisible();
  await expect(
    page.getByRole("cell", { name: "PENDING PASSWORD" }),
  ).toBeVisible();
  await page
    .getByRole("row", { name: new RegExp(username) })
    .getByRole("link")
    .click();
  await expect(
    page.getByText("Activation is unavailable until password enrollment"),
  ).toBeVisible();
  await page.goto(`/admin/staff/${process.env.LUMINA_E2E_SUPER_ID}`);
  await expect(page.getByText("This page could not be found")).toBeVisible();

  await page.goto(`/admin/staff/${process.env.LUMINA_E2E_ADMIN_ID}`);
  await page.getByLabel("Display name").fill("E2E Administrator Updated");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test("supervisor receives a restricted staff directory projection", async ({
  page,
}) => {
  await signInWith(
    page,
    process.env.LUMINA_E2E_SUPERVISOR_USERNAME,
    process.env.LUMINA_E2E_SUPERVISOR_PASSWORD,
  );
  await page.goto(
    `/admin/staff?query=${encodeURIComponent(process.env.LUMINA_E2E_SUPER_USERNAME!)}`,
  );
  await expect(
    page.getByRole("heading", { name: "Staff directory" }),
  ).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Email" })).toHaveCount(
    0,
  );
  await expect(page.getByText("E2E Protected Administrator")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Create staff" })).toHaveCount(0);
});

test("Super Administrator can access protected staff and role creation", async ({
  page,
}) => {
  await signInWith(
    page,
    process.env.LUMINA_E2E_SUPER_USERNAME,
    process.env.LUMINA_E2E_SUPER_PASSWORD,
  );
  await page.goto(
    `/admin/staff?query=${encodeURIComponent(process.env.LUMINA_E2E_SUPER_USERNAME!)}`,
  );
  await expect(page.getByText("E2E Protected Administrator")).toBeVisible();
  await page.goto("/admin/roles/new");
  await expect(
    page.getByRole("heading", { name: "Create configurable role" }),
  ).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.locator(":focus")).toBeVisible();
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

async function signInWith(
  page: import("@playwright/test").Page,
  identifier: string | undefined,
  fixturePassword: string | undefined,
) {
  expect(identifier).toBeTruthy();
  expect(fixturePassword).toBeTruthy();
  await page.goto("/login");
  await page.getByLabel("Username or email").fill(identifier!);
  await page.getByLabel("Password").fill(fixturePassword!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
}
