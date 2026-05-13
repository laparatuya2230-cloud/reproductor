const tableBody = document.querySelector("#quoteItemsTable tbody");
const addButton = document.getElementById("addItemButton");
const form = document.getElementById("quoteForm");
const equipmentCodeInput = document.getElementById("equipmentCodeInput");
const checkEquipmentButton = document.getElementById("checkEquipmentButton");
const equipmentPreview = document.getElementById("equipmentPreview");
const laborCostInput = document.querySelector("input[name='labor_cost']");
const discountInput = document.querySelector("input[name='discount_percent']");
const previewPartsSubtotal = document.getElementById("previewPartsSubtotal");
const previewLaborCost = document.getElementById("previewLaborCost");
const previewDiscountPercent = document.getElementById("previewDiscountPercent");
const previewDiscountAmount = document.getElementById("previewDiscountAmount");
const previewQuoteTotal = document.getElementById("previewQuoteTotal");

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase();
}

function setEquipmentPreviewHtml(html) {
  if (equipmentPreview) {
    equipmentPreview.innerHTML = html;
  }
}

function formatMoneyLikeNumber(value) {
  return Number(value || 0).toFixed(2);
}

function refreshQuoteTotals() {
  if (!tableBody) {
    return;
  }

  let partsSubtotal = 0;
  const rows = tableBody.querySelectorAll("tr");
  rows.forEach((row) => {
    const price = Number(row.querySelector(".part-price-input")?.value || 0);
    const qty = Number(row.querySelector("input[name='item_quantity']")?.value || 0);
    partsSubtotal += price * qty;
  });

  const labor = Number(laborCostInput?.value || 0);
  const baseSubtotal = partsSubtotal + labor;
  const discountPercent = Math.min(100, Math.max(0, Number(discountInput?.value || 0)));
  const discountAmount = baseSubtotal * (discountPercent / 100);
  const total = Math.max(0, baseSubtotal - discountAmount);

  if (previewPartsSubtotal) {
    previewPartsSubtotal.textContent = formatMoneyLikeNumber(partsSubtotal);
  }
  if (previewLaborCost) {
    previewLaborCost.textContent = formatMoneyLikeNumber(labor);
  }
  if (previewDiscountPercent) {
    previewDiscountPercent.textContent = `${formatMoneyLikeNumber(discountPercent)}%`;
  }
  if (previewDiscountAmount) {
    previewDiscountAmount.textContent = formatMoneyLikeNumber(discountAmount);
  }
  if (previewQuoteTotal) {
    previewQuoteTotal.textContent = formatMoneyLikeNumber(total);
  }
}

async function checkEquipmentByCode() {
  if (!equipmentCodeInput) {
    return;
  }
  const code = normalizeCode(equipmentCodeInput.value);
  equipmentCodeInput.value = code;
  if (!code) {
    setEquipmentPreviewHtml("<p class='small-text'>Escribe un codigo unico para buscar el equipo.</p>");
    return;
  }

  try {
    const response = await fetch(`/api/equipos/por-codigo/${encodeURIComponent(code)}`);
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      setEquipmentPreviewHtml(`<p class='small-text'>${payload.message || "No se encontro el equipo."}</p>`);
      return;
    }
    const item = payload.data;
    setEquipmentPreviewHtml(`
      <p><strong>Equipo:</strong> ${item.code} | ${item.equipment_name}</p>
      <p><strong>Cliente:</strong> ${item.customer_name} - ${item.customer_phone}</p>
      <p><strong>Estado actual:</strong> <span class="state-badge">${item.status}</span></p>
    `);
  } catch (_error) {
    setEquipmentPreviewHtml("<p class='small-text'>No se pudo validar el equipo en este momento.</p>");
  }
}

function resetPartRow(row) {
  const codeInput = row.querySelector(".part-code-input");
  const quantityInput = row.querySelector("input[name='item_quantity']");
  const priceInput = row.querySelector(".part-price-input");
  const hint = row.querySelector(".part-name-hint");
  if (codeInput) {
    codeInput.value = "";
    codeInput.setCustomValidity("");
  }
  if (quantityInput) {
    quantityInput.value = "1";
  }
  if (priceInput) {
    priceInput.value = "0";
  }
  if (hint) {
    hint.textContent = "";
  }
}

async function syncPartRow(row) {
  const codeInput = row.querySelector(".part-code-input");
  const priceInput = row.querySelector(".part-price-input");
  const hint = row.querySelector(".part-name-hint");
  if (!codeInput || !priceInput || !hint) {
    return;
  }

  const code = normalizeCode(codeInput.value);
  codeInput.value = code;
  codeInput.setCustomValidity("");

  if (!code) {
    priceInput.value = "0";
    hint.textContent = "";
    hint.classList.remove("error-text");
    refreshQuoteTotals();
    return;
  }

  try {
    const response = await fetch(`/api/inventario/por-codigo/${encodeURIComponent(code)}`);
    const payload = await response.json();

    if (!response.ok || !payload.ok) {
      priceInput.value = "0";
      hint.textContent = `La pieza ${code} no esta registrada.`;
      hint.classList.add("error-text");
      codeInput.setCustomValidity(`La pieza ${code} no esta registrada.`);
      refreshQuoteTotals();
      return;
    }

    const part = payload.data;
    priceInput.value = Number(part.sale_price || 0).toFixed(2);
    hint.textContent = `${part.part_name} | Precio de venta: ${Number(part.sale_price || 0).toFixed(2)}`;
    hint.classList.remove("error-text");
    refreshQuoteTotals();
  } catch (_error) {
    priceInput.value = "0";
    hint.textContent = "No se pudo consultar inventario ahora.";
    hint.classList.add("error-text");
    refreshQuoteTotals();
  }
}

function buildRow() {
  const row = document.createElement("tr");
  row.innerHTML = `
    <td>
      <input type="text" name="item_part_code" class="part-code-input" list="partsCatalog" placeholder="Ejemplo: 3205" />
      <small class="part-name-hint"></small>
    </td>
    <td><input type="number" name="item_quantity" step="1" min="0" value="1" /></td>
    <td><input type="number" name="item_price" class="part-price-input" step="0.01" min="0" value="0" readonly /></td>
    <td><button class="button mini danger remove-item" type="button">X</button></td>
  `;
  return row;
}

if (tableBody && addButton) {
  addButton.addEventListener("click", () => {
    tableBody.appendChild(buildRow());
    refreshQuoteTotals();
  });

  tableBody.addEventListener("click", (event) => {
    const button = event.target.closest(".remove-item");
    if (!button) {
      return;
    }
    const rows = tableBody.querySelectorAll("tr");
    if (rows.length === 1) {
      resetPartRow(rows[0]);
      refreshQuoteTotals();
      return;
    }
    button.closest("tr")?.remove();
    refreshQuoteTotals();
  });

  tableBody.addEventListener("change", (event) => {
    const target = event.target;
    if (target && target.classList.contains("part-code-input")) {
      const row = target.closest("tr");
      if (row) {
        syncPartRow(row);
      }
    }
    if (target && target.name === "item_quantity") {
      refreshQuoteTotals();
    }
  });

  tableBody.addEventListener("input", (event) => {
    const target = event.target;
    if (target && target.name === "item_quantity") {
      refreshQuoteTotals();
    }
  });

  const preloadRows = tableBody.querySelectorAll("tr");
  preloadRows.forEach((row) => {
    syncPartRow(row);
  });
  refreshQuoteTotals();
}

if (checkEquipmentButton) {
  checkEquipmentButton.addEventListener("click", () => {
    checkEquipmentByCode();
  });
}

if (form) {
  form.addEventListener("submit", async (event) => {
    if (!tableBody) {
      return;
    }
    const rows = Array.from(tableBody.querySelectorAll("tr"));
    for (const row of rows) {
      await syncPartRow(row);
    }
    if (!form.checkValidity()) {
      event.preventDefault();
      form.reportValidity();
    }
  });
}

if (laborCostInput) {
  laborCostInput.addEventListener("input", refreshQuoteTotals);
}
if (discountInput) {
  discountInput.addEventListener("input", refreshQuoteTotals);
}
