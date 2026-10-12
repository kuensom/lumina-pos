import { expect, test } from "@playwright/test";

test("dashboard foundation is visible", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Lumina POS dashboard" }),
  ).toBeVisible();
  await expect(
    page.getByText("Operational POS features are not implemented"),
  ).toBeVisible();
});

test("login is clearly nonfunctional", async ({ page }) => {
  await page.goto("/login");

  await expect(
    page.getByRole("heading", { name: "Sign in to Lumina POS" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sign in unavailable" }),
  ).toBeDisabled();
  await expect(
    page.getByText("Authentication is not implemented"),
  ).toBeVisible();
});

test("health endpoint reports the service status", async ({ request }) => {
  const response = await request.get("/api/health");

  expect(response.ok()).toBe(true);
  await expect(response.json()).resolves.toEqual({
    status: "ok",
    service: "lumina-pos",
  });
});
