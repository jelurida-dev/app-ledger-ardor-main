/*
 * Copyright © 2016-2023 Jelurida IP B.V.
 * Copyright © 2023-2026 Jelurida Swiss SA
 *
 * See the LICENSE.txt file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with Jelurida
 * Swiss SA, no part of this software, including this file, may be copied,
 * modified, propagated, or distributed except according to the terms
 * contained in the LICENSE.txt file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */

package com.jelurida.ardor.integration.wallet.ledger.speculos;

import nxt.addons.JO;
import nxt.util.Logger;
import org.junit.Assert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Drives the Ardor app running on the Speculos emulator: reads the screen and presses the
 * buttons over the Speculos REST API, which is reached at <code>speculos.apiUrl</code>
 * (default <code>http://localhost:5000</code>).
 * <p>
 * Navigation is content driven: a review is walked until its confirmation screen shows up
 * instead of pressing a hardcoded number of times, so the same code works whatever a device
 * pages the text into.
 * <p>
 * The screens and the two buttons below are the Nano ones, drawn by the app's BAGL stack
 * (src/ui/*_bagl.c). The touch devices are a different state machine — NBGL offers to enable
 * blind signing inline instead of refusing — and are covered by the Ragger tests instead.
 */
public class SpeculosRemote {

    private static final List<String> HOME_SCREEN = Arrays.asList("Application", "is ready");
    private static final List<String> SETTINGS_HOME_ENTRY = Arrays.asList("Settings");
    private static final List<String> SETTINGS_MENU = Arrays.asList("Allow blind signing", "Back");
    private static final List<String> BLIND_SIGNING_MENU = Arrays.asList("No", "Yes", "Back");
    private static final List<String> BLIND_SIGNING_DISABLED_SCREEN =
            Arrays.asList("Blind signing must be", "enabled on Settings");

    /** The " (2/3)" a paging screen appends to its title. */
    private static final Pattern PAGE_NUMBER = Pattern.compile(" \\(\\d+/\\d+\\)$");

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final long SCREEN_TIMEOUT_MILLIS = 15_000;
    private static final long POLL_INTERVAL_MILLIS = 50;
    private static final int MAX_REVIEW_SCREENS = 30;

    private final String apiUrl = System.getProperty("speculos.apiUrl", "http://localhost:5000");
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /** Waits for the app to be back at its home screen. */
    public void awaitHomeScreen() {
        awaitScreen(HOME_SCREEN);
    }

    /**
     * Waits for the app to react to a signing command and reports whether it refused because
     * blind signing is disabled. The refusal screen is dismissed, leaving the app at home.
     */
    public boolean blindSigningRefused() {
        if (!BLIND_SIGNING_DISABLED_SCREEN.equals(awaitReaction())) {
            return false;
        }
        pressBoth();
        awaitHomeScreen();
        return true;
    }

    /** Turns the "Allow blind signing" setting on, from the home screen and back to it. */
    public void enableBlindSigning() {
        awaitHomeScreen();
        pressRight();
        awaitScreen(SETTINGS_HOME_ENTRY);
        pressBoth();
        awaitScreen(SETTINGS_MENU);
        pressBoth();
        awaitScreen(BLIND_SIGNING_MENU);
        pressRight();  // move the selection from "No" to "Yes"
        pressBoth();
        awaitScreen(SETTINGS_MENU);
        pressRight();  // move the selection from "Allow blind signing" to "Back"
        pressBoth();
        awaitHomeScreen();
    }

    /**
     * The text one review screen contributes to what {@link #reviewAndConfirm} checks: its
     * title followed by its lines, with nothing in between. Build the expected screens with
     * this rather than passing titles and values separately, so that a value is anchored to
     * its title and cannot match as the tail of a different one.
     */
    public static String screen(String title, String... lines) {
        return title + String.join("", lines);
    }

    /**
     * Walks the review the app is showing, checks that the given screens appear on it in that
     * order, and confirms it on the screen titled confirmLabel ("Accept", "Sign", "Confirm").
     * Leaves the app at its home screen.
     */
    public void reviewAndConfirm(String confirmLabel, String... expectedTexts) {
        StringBuilder review = new StringBuilder();
        List<String> screen = awaitReaction();
        String previousTitle = null;
        for (int i = 0; !confirmLabel.equals(screen.get(0)); i++) {
            Assert.assertTrue(String.format("No \"%s\" screen after %d screens, showing %s, review so far: %s",
                                            confirmLabel, i, screen, review),
                              i < MAX_REVIEW_SCREENS);
            previousTitle = appendScreen(review, screen, previousTitle);
            screen = pressRightAndAwaitNewScreen(screen);
        }
        Logger.logInfoMessage("Review screens read from Speculos: %s", review);
        assertContainsInOrder(review.toString(), expectedTexts);
        pressBoth();
        awaitHomeScreen();
    }

    private void pressRight() {
        pressButton("right");
    }

    private void pressBoth() {
        pressButton("both");
    }

    /**
     * Appends one review screen to the text collected so far and returns its title. Values
     * split over several lines or pages are concatenated back into one string, so the title
     * a paging screen repeats on its continuation pages is appended only once.
     */
    private static String appendScreen(StringBuilder review, List<String> screen, String previousTitle) {
        String title = PAGE_NUMBER.matcher(screen.get(0)).replaceFirst("");
        if (!title.equals(previousTitle)) {
            review.append(title);
        }
        screen.subList(1, screen.size()).forEach(review::append);
        return title;
    }

    private static void assertContainsInOrder(String review, String... expectedTexts) {
        int from = 0;
        for (String expectedText : expectedTexts) {
            int index = review.indexOf(expectedText, from);
            Assert.assertTrue(String.format("\"%s\" not shown (in this order) by the review: %s", expectedText, review),
                              index >= 0);
            from = index + expectedText.length();
        }
    }

    /** Waits for the app to show something other than its home screen. */
    private List<String> awaitReaction() {
        return awaitScreen(screen -> !screen.isEmpty() && !HOME_SCREEN.equals(screen), "anything but the home screen");
    }

    private List<String> awaitScreen(List<String> expectedScreen) {
        return awaitScreen(expectedScreen::equals, expectedScreen.toString());
    }

    private List<String> pressRightAndAwaitNewScreen(List<String> currentScreen) {
        pressRight();
        return awaitScreen(screen -> !screen.isEmpty() && !currentScreen.equals(screen),
                           "a screen other than " + currentScreen);
    }

    private List<String> awaitScreen(Predicate<List<String>> isExpected, String description) {
        long deadline = System.currentTimeMillis() + SCREEN_TIMEOUT_MILLIS;
        List<String> screen = currentScreen();
        do {
            sleep();
            List<String> nextScreen = currentScreen();
            // Speculos grows the event list as the app draws the screen, so a read taken
            // mid-draw returns only part of it. Trust a screen two reads in a row agree on.
            if (screen.equals(nextScreen) && isExpected.test(screen)) {
                return screen;
            }
            screen = nextScreen;
        } while (System.currentTimeMillis() < deadline);
        throw new AssertionError(String.format("Timed out waiting for %s, Speculos shows %s", description, screen));
    }

    private List<String> currentScreen() {
        return JO.parse(get("/events?currentscreenonly=true")).getArray("events").objects().stream()
                 .map(event -> event.getString("text"))
                 .collect(Collectors.toList());
    }

    private void pressButton(String button) {
        send(HttpRequest.newBuilder()
                        .uri(URI.create(apiUrl + "/button/" + button))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"action\":\"press-and-release\"}")));
    }

    private String get(String path) {
        return send(HttpRequest.newBuilder().uri(URI.create(apiUrl + path)).GET());
    }

    private String send(HttpRequest.Builder request) {
        try {
            HttpResponse<String> response = httpClient.send(request.timeout(REQUEST_TIMEOUT).build(),
                                                            HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException(String.format("Speculos answered %d to %s: %s",
                                                              response.statusCode(), response.uri(), response.body()));
            }
            return response.body();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot reach Speculos at " + apiUrl, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void sleep() {
        try {
            Thread.sleep(POLL_INTERVAL_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
