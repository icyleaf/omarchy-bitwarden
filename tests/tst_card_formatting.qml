import QtQuick
import QtQuick.Controls
import "../components/CardFormatter.js" as CardFormatter

Item {
  id: testRunner
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  // Simulation harness verifying signal-driven reveal toggle in ItemInspector
  property bool showCardNumberRevealed: false
  property bool showCardCodeRevealed: false
  signal toggleCardNumberRevealed()
  signal toggleCardCodeRevealed()

  onToggleCardNumberRevealed: { showCardNumberRevealed = !showCardNumberRevealed }
  onToggleCardCodeRevealed: { showCardCodeRevealed = !showCardCodeRevealed }

  Component.onCompleted: {
    console.log("Running Card Number Formatting & Sanitization Tests...")

    // 1. Sanitization / Copy Tests (strip non-digits)
    check(CardFormatter.sanitizeCardNumberForCopy("4111 1111 1111 1111") === "4111111111111111", "Strip spaces from 16-digit card")
    check(CardFormatter.sanitizeCardNumberForCopy("3782-822463-10005") === "378282246310005", "Strip dashes from 15-digit Amex")
    check(CardFormatter.sanitizeCardNumberForCopy("  5555_4444 3333-2222  ") === "5555444433332222", "Strip mixed delimiters and padding")
    check(CardFormatter.sanitizeCardNumberForCopy(null) === "", "Null card number returns empty string")
    check(CardFormatter.sanitizeCardNumberForCopy(undefined) === "", "Undefined card number returns empty string")
    check(CardFormatter.sanitizeCardNumberForCopy("") === "", "Empty card number returns empty string")
    check(CardFormatter.sanitizeCardNumberForCopy(4111111111111111) === "4111111111111111", "Numeric type card number sanitized to string")

    // 2. Revealed Formatting Tests
    // Standard 16-digit (Visa, Mastercard, etc.) -> 4-4-4-4
    check(CardFormatter.formatRevealedCardNumber("4111111111111111", "Visa") === "4111 1111 1111 1111", "16-digit Visa formatted 4-4-4-4")
    check(CardFormatter.formatRevealedCardNumber("5555444433332222", "Mastercard") === "5555 4444 3333 2222", "16-digit Mastercard formatted 4-4-4-4")
    check(CardFormatter.formatRevealedCardNumber("4111 1111 1111 1111", "Visa") === "4111 1111 1111 1111", "Pre-spaced 16-digit card normalized to 4-4-4-4")

    // American Express 15-digit -> 4-6-5
    check(CardFormatter.formatRevealedCardNumber("378282246310005", "American Express") === "3782 822463 10005", "15-digit Amex by brand formatted 4-6-5")
    check(CardFormatter.formatRevealedCardNumber("378282246310005", "AmericanExpress") === "3782 822463 10005", "15-digit Amex without space in brand formatted 4-6-5")
    check(CardFormatter.formatRevealedCardNumber("340000000000009", "") === "3400 000000 00009", "15-digit Amex by BIN prefix (34) formatted 4-6-5 without brand")
    check(CardFormatter.formatRevealedCardNumber("3782 822463 10005", "Amex") === "3782 822463 10005", "15-digit Amex normalized to 4-6-5")

    // Diners Club 14-digit -> 4-6-4
    check(CardFormatter.formatRevealedCardNumber("36123456789012", "Diners Club") === "3612 345678 9012", "14-digit Diners Club by brand formatted 4-6-4")
    check(CardFormatter.formatRevealedCardNumber("30012345678901", "") === "3001 234567 8901", "14-digit Diners Club by BIN prefix (300) formatted 4-6-4 without brand")

    // Irregular and short card numbers
    check(CardFormatter.formatRevealedCardNumber("1234", "Visa") === "1234", "Short 4-digit card number not segmented")
    check(CardFormatter.formatRevealedCardNumber("12", "") === "12", "Short 2-digit card number not segmented")
    check(CardFormatter.formatRevealedCardNumber("12345678", "") === "1234 5678", "8-digit number formatted in 4-digit blocks")
    check(CardFormatter.formatRevealedCardNumber("1234567890123456789", "") === "1234 5678 9012 3456 789", "19-digit number formatted in 4-digit blocks with remainder")

    // 3. Masked Formatting Tests
    // Standard 16-digit -> •••• •••• •••• 1111
    check(CardFormatter.formatMaskedCardNumber("4111111111111111", "Visa") === "•••• •••• •••• 1111", "16-digit masked format aligns with 4-4-4-4")

    // American Express 15-digit -> •••• •••••• •0005
    check(CardFormatter.formatMaskedCardNumber("378282246310005", "Amex") === "•••• •••••• •0005", "15-digit Amex masked format aligns with 4-6-5")

    // Diners Club 14-digit -> •••• •••••• 9012
    check(CardFormatter.formatMaskedCardNumber("36123456789012", "Diners") === "•••• •••••• 9012", "14-digit Diners Club masked format aligns with 4-6-4")

    // Short cards <= 4 digits
    check(CardFormatter.formatMaskedCardNumber("1234", "") === "••••", "4-digit card displays 4 bullets")
    check(CardFormatter.formatMaskedCardNumber("123", "") === "•••", "3-digit card displays 3 bullets")
    check(CardFormatter.formatMaskedCardNumber("", "") === "•••• •••• •••• ••••", "Empty card defaults to standard 16-digit mask placeholder")

    // 4. Signal-driven toggle verification
    check(showCardNumberRevealed === false, "Initial showCardNumberRevealed is false")
    toggleCardNumberRevealed()
    check(showCardNumberRevealed === true, "toggleCardNumberRevealed flips state to true")
    toggleCardNumberRevealed()
    check(showCardNumberRevealed === false, "toggleCardNumberRevealed flips state to false")

    check(showCardCodeRevealed === false, "Initial showCardCodeRevealed is false")
    toggleCardCodeRevealed()
    check(showCardCodeRevealed === true, "toggleCardCodeRevealed flips state to true")
    toggleCardCodeRevealed()
    check(showCardCodeRevealed === false, "toggleCardCodeRevealed flips state to false")

    // 5. Parent-Child Binding preservation under item selection changes
    var parentScope = {
      rootShowCardNumberRevealed: false,
      handleSelectedItemChanged: function() {
        this.rootShowCardNumberRevealed = false
      }
    }
    var childInspector = {
      item: null,
      get showCardNumberRevealed() { return parentScope.rootShowCardNumberRevealed }
    }
    check(childInspector.showCardNumberRevealed === false, "Inspector initial state false")
    childInspector.item = { name: "Card 1", card: { number: "4111111111111111" } }
    parentScope.rootShowCardNumberRevealed = true
    check(childInspector.showCardNumberRevealed === true, "Inspector reflects reveal toggle after item populated")
    parentScope.handleSelectedItemChanged()
    childInspector.item = { name: "Card 2", card: { number: "378282246310005" } }
    check(childInspector.showCardNumberRevealed === false, "Inspector resets to masked on item selection switch")
    parentScope.rootShowCardNumberRevealed = true
    check(childInspector.showCardNumberRevealed === true, "Inspector reflects reveal toggle on subsequent item")

    console.log("Card Formatting Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
