# i18n Altyapisi + Turkce Dil Destegi

**Tarih:** 2026-03-11
**Durum:** Onaylandi
**Kapsam:** Flutter uygulamasi (lib/)

---

## Ozet

Flutter uygulamasina Flutter gen-l10n tabanli coklu dil destegi eklenmesi. Ilk diller: Ingilizce (kaynak) + Turkce. Gelecekte kolayca yeni dil eklenebilir.

## Gereksinimler

1. **Genel i18n altyapisi** — Turkce ilk dil, gelecekte baska diller eklenebilsin
2. **Dil secimi:** Sistem varsayilani + Settings'ten override (System default / English / Turkce)
3. **Kapsam:** Tum ~35 ekrandaki tum string'ler tek seferde
4. **Fallback:** Desteklenmeyen dillerde Ingilizce
5. **Ceviriler:** Claude taslak cevirir, kullanici review eder

## Teknik Yaklasim

**Framework:** Flutter gen-l10n (resmi Flutter cozumu)
- `flutter_localizations` SDK dependency (BSD-3, Flutter SDK'nin parcasi)
- `intl` paketi zaten pubspec.yaml'da mevcut
- Ek 3rd-party dependency yok

## Dosya Yapisi

```
lib/l10n/
  app_en.arb          # Ingilizce (kaynak dil)
  app_tr.arb          # Turkce

l10n.yaml             # gen-l10n konfigurasyonu (proje kokunde)

lib/providers/
  locale_provider.dart  # Dil secimi state (SharedPreferences ile persist)
```

## l10n.yaml Konfigurasyonu

```yaml
arb-dir: lib/l10n
template-arb-file: app_en.arb
output-localization-file: app_localizations.dart
output-class: AppLocalizations
nullable-getter: false
```

`nullable-getter: false` sayesinde `AppLocalizations.of(context)` null donmez, `!` operatoru gerekmez.

## MaterialApp Degisiklikleri

```dart
MaterialApp(
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  supportedLocales: AppLocalizations.supportedLocales,
  locale: ref.watch(localeProvider),  // null = sistem varsayilani
  // mevcut: theme, darkTheme, themeMode, ...
)
```

## Dil Secimi Akisi

```
Uygulama acilis:
  SharedPreferences'ta kayitli locale var mi?
    Evet -> O locale'i kullan
    Hayir -> Sistem locale'ini kontrol et
              tr -> Turkce
              Diger -> Ingilizce (fallback)

Settings ekrani:
  Dil secimi dropdown -> ["System default", "English", "Turkce"]
  Secim -> localeProvider guncelle -> SharedPreferences'a kaydet -> UI rebuild
```

## locale_provider.dart

Riverpod StateNotifier + SharedPreferences:
- `null` = sistem varsayilani
- `Locale('en')` = Ingilizce
- `Locale('tr')` = Turkce
- Uygulama acilisinda SharedPreferences'tan yukle
- Degisiklikte hem provider'i hem SharedPreferences'i guncelle

## ARB Dosya Formati

```json
// app_en.arb
{
  "@@locale": "en",
  "appTitle": "DNA Messenger",
  "navHome": "Home",
  "navChats": "Chats",
  "messageCount": "{count, plural, =0{No messages} =1{1 message} other{{count} messages}}",
  "@messageCount": {
    "placeholders": {
      "count": { "type": "int" }
    }
  }
}
```

ICU format: plural, parameterized string destegi.

## String Extraction Kapsami

| Grup | Ekranlar | Tahmini String Sayisi |
|------|----------|----------------------|
| Mesajlasma | messages_screen, chat_screen, message_bubble, message_context_menu | ~40-50 |
| Kisiler | contacts_screen, contacts_hub, contact_requests, add_contact_dialog, contact_profile_dialog | ~30-40 |
| Kanallar | channel_list, channel_detail, create_channel, discover_channels | ~25-30 |
| Gruplar | groups_screen | ~15-20 |
| Ayarlar | settings_screen, app_lock_settings, blocked_users, contacts_management, starred_messages | ~30-40 |
| Profil | profile_editor, avatar_crop | ~10-15 |
| Kimlik | identity_selection | ~10-15 |
| Wall | wall_timeline, wall_post_detail | ~15-20 |
| Wallet | wallet_screen, address_dialog, address_book | ~20-30 |
| QR | qr_scanner, qr_auth, qr_result | ~10-15 |
| Diger | home_screen, more_screen, lock_screen, update_required | ~10-15 |

**Toplam: ~220-290 string**

## Settings UI

Mevcut settings_screen.dart'a yeni satir:
```
Language / Dil
  System default (Sistem varsayilani)
  English
  Turkce
```

## Kullanim Paterni (Ekranlarda)

```dart
import 'package:flutter_gen/gen_l10n/app_localizations.dart';

// Widget icinde:
Text(AppLocalizations.of(context).chatTitle)
```

## Reddedilen Alternatifler

- **easy_localization**: Runtime string lookup, type safety yok, ekstra dependency
- **intl_utils**: Daha fazla boilerplate, Flutter team artik gen-l10n'i oneriyor

## Notlar

- C library, CLI, log mesajlari ETKILENMEZ (sadece Flutter UI)
- Turkce cevirilerde teknik terimler gosterilmeyecek (mevcut Non-Technical User Design kurali)
- Yeni ekran eklendiginde hem app_en.arb hem app_tr.arb guncellenmeli
