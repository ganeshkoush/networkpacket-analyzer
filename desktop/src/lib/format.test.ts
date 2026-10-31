import { describe, expect, it } from "vitest";
import { endpoint, formatMs, formatBytes, formatDuration, formatNumber, formatOffset, formatPercent, formatTime, humanizeKey } from "./format";
import { countBySeverity, typeLabel } from "./severity";

describe("format", () => {
  it("formats numbers and nulls", () => {
    expect(formatNumber(1234567)).toBe("1,234,567");
    expect(formatNumber(null)).toBe("–");
  });
  it("formats bytes across units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GB");
    expect(formatBytes(2048 * 1024 ** 4)).toContain("TB");
  });
  it("formats durations", () => {
    expect(formatDuration(0.25)).toBe("250 ms");
    expect(formatDuration(8.6)).toBe("8.60 s");
    expect(formatDuration(75)).toBe("1m 15s");
    expect(formatDuration(3725)).toBe("1h 2m 5s");
    expect(formatDuration(undefined)).toBe("–");
  });
  it("formats time, offsets, percent, keys, endpoints", () => {
    expect(formatTime(1_700_000_000)).toBe("2023-11-14 22:13:20 UTC");
    expect(formatTime(null)).toBe("–");
    expect(formatOffset(75)).toBe("1:15");
    expect(formatOffset(3725)).toBe("1:02:05");
    expect(formatPercent(0.1234)).toBe("12.3%");
    expect(humanizeKey("syn_ack_packets")).toBe("syn ack packets");
    expect(endpoint("1.1.1.1", 53)).toBe("1.1.1.1:53");
    expect(endpoint("1.1.1.1", null)).toBe("1.1.1.1");
    expect(formatMs(45)).toBe("45 ms");
    expect(formatMs(7.04)).toBe("7 ms");
    expect(formatMs(52.46)).toBe("52.5 ms");
    expect(formatMs(0)).toBe("0 ms");
    expect(formatMs(1250)).toBe("1.25 s");
    expect(formatMs(null)).toBe("–");
    expect(endpoint("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
  });
});

describe("severity helpers", () => {
  it("counts by severity", () => {
    expect(countBySeverity([{ severity: "HIGH" }, { severity: "HIGH" }, { severity: "INFO" }])).toEqual({ CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 1 });
  });
  it("labels finding types", () => {
    expect(typeLabel("PORT_SCAN")).toBe("Port scan");
    expect(typeLabel("DNS_DGA_LIKE")).toBe("DNS DGA-like");
    expect(typeLabel("DNS_HIGH_NXDOMAIN")).toBe("DNS high NXDOMAIN");
    expect(typeLabel("DNS_TUNNELING_LIKE")).toBe("DNS tunneling-like");
    expect(typeLabel("SYN_FLOOD")).toBe("SYN flood");
    expect(typeLabel("ARP_SPOOFING")).toBe("ARP spoofing");
  });
});
