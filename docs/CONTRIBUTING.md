# Katkı Rehberi

1. Depoyu çatallayın, bir dal açın.
2. Yeni davranış eklerken bir test de ekleyin (`engine/tests/`).
3. `pytest -q engine/tests` ve `node --check web/sim.js` geçmeli.
4. Gerçek sistemlere yönelik kullanım, bu projenin kapsamı dışındadır; katkılar yalnızca
   modelin doğruluğunu, eğitim değerini ve belgelendirmeyi geliştirmelidir.
