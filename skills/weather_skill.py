"""
ARGUS - Weather.

Uses Open-Meteo: free, no API key, no account. Note this is one of the few
places ARGUS reaches the internet — the request contains a city name and
nothing else, but it does leave the machine. The AI reasoning stays local.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import requests

from config import DEFAULT_CITY

GEO_URL = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST_URL = "https://api.open-meteo.com/v1/forecast"

# WMO weather interpretation codes
WMO = {
    0: "clear", 1: "mostly clear", 2: "partly cloudy", 3: "overcast",
    45: "foggy", 48: "freezing fog",
    51: "light drizzle", 53: "drizzle", 55: "heavy drizzle",
    56: "freezing drizzle", 57: "heavy freezing drizzle",
    61: "light rain", 63: "rain", 65: "heavy rain",
    66: "freezing rain", 67: "heavy freezing rain",
    71: "light snow", 73: "snow", 75: "heavy snow", 77: "snow grains",
    80: "light showers", 81: "showers", 82: "violent showers",
    85: "snow showers", 86: "heavy snow showers",
    95: "thunderstorms", 96: "thunderstorms with hail", 99: "severe thunderstorms",
}


def _geocode(city: str):
    r = requests.get(GEO_URL, params={"name": city, "count": 1}, timeout=10)
    r.raise_for_status()
    results = r.json().get("results")
    if not results:
        return None
    top = results[0]
    return top["latitude"], top["longitude"], top["name"], top.get("country", "")


def get_weather(city: str = "") -> str:
    city = (city or DEFAULT_CITY).strip()
    try:
        geo = _geocode(city)
        if not geo:
            return f"I couldn't find a place called {city}."
        lat, lon, name, country = geo

        r = requests.get(
            FORECAST_URL,
            params={
                "latitude": lat,
                "longitude": lon,
                "current": "temperature_2m,apparent_temperature,weather_code,wind_speed_10m",
                "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max",
                "timezone": "auto",
                "forecast_days": 1,
            },
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()

        cur = data["current"]
        daily = data["daily"]

        temp = round(cur["temperature_2m"])
        feels = round(cur["apparent_temperature"])
        desc = WMO.get(cur["weather_code"], "unclear conditions")
        wind = round(cur["wind_speed_10m"])
        hi = round(daily["temperature_2m_max"][0])
        lo = round(daily["temperature_2m_min"][0])
        rain = daily["precipitation_probability_max"][0]

        out = f"In {name} it's {temp} degrees and {desc}"
        if abs(feels - temp) >= 3:
            out += f", feels like {feels}"
        out += f". High {hi}, low {lo}."
        if rain is not None and rain >= 30:
            out += f" {rain} percent chance of precipitation."
        if wind >= 30:
            out += f" Windy at {wind} kilometres per hour."
        return out

    except requests.exceptions.RequestException as e:
        return f"I couldn't reach the weather service: {e}"
    except (KeyError, IndexError, ValueError) as e:
        return f"The weather data came back in an unexpected shape: {e}"
