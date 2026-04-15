import 'package:dna_connect/widgets/wall_post_tile.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('heatValueForLikes', () {
    test('returns 0 for zero likes', () {
      expect(heatValueForLikes(0), 0.0);
    });

    test('returns 0 for negative likes', () {
      expect(heatValueForLikes(-5), 0.0);
    });

    test('1 like maps to ~0.15 (visible from first like)', () {
      expect(heatValueForLikes(1), closeTo(0.15, 0.01));
    });

    test('10 likes maps to ~0.52', () {
      expect(heatValueForLikes(10), closeTo(0.52, 0.02));
    });

    test('50 likes maps to ~0.85', () {
      expect(heatValueForLikes(50), closeTo(0.85, 0.02));
    });

    test('100 likes saturates at 1.0', () {
      expect(heatValueForLikes(100), 1.0);
    });

    test('200 likes also saturates at 1.0 (clamped)', () {
      expect(heatValueForLikes(200), 1.0);
    });

    test('monotonically non-decreasing', () {
      final values = <double>[
        for (final n in [1, 5, 10, 25, 50, 75, 99, 100])
          heatValueForLikes(n),
      ];
      for (var i = 1; i < values.length; i++) {
        expect(values[i], greaterThanOrEqualTo(values[i - 1]));
      }
    });
  });
}
