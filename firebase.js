/* ======================================================================
   DLM | دلم — firebase.js
   ======================================================================
   هذا الملف يحتوي على كل منطق المشروع المرتبط بـ Firebase بالإضافة إلى
   منطق الموقع نفسه (التوجيه، العرض، لوحة التحكم، تأثير الكتابة العربي).

   الأقسام:
   0) تهيئة Firebase (Auth + Firestore + Storage)
   1) طبقة المصادقة (Authentication Layer)
   2) طبقة قاعدة البيانات (Firestore Data Layer) — CRUD كامل
   3) طبقة رفع الصور (Storage Layer)
   4) أدوات مساعدة عامة (تنسيق، تنبيهات، تحقق من المدخلات)
   5) نظام الترجمة (i18n)
   6) نظام التوجيه بين الصفحات (Router)
   7) عرض محتوى الصفحة الرئيسية + تأثير الكتابة العربي المُصحَّح
   8) صفحة القصيدة الفردية + المشاركة
   9) صفحة الأرشيف / التصنيفات / الاقتباسات / البحث
   10) تسجيل الدخول الآمن عبر Firebase Auth + حماية لوحة التحكم
   11) لوحة التحكم: الإحصائيات + CRUD القصائد/التصنيفات/الاقتباسات
   12) ربط عناصر التنقل العامة + التشغيل الأولي
   ====================================================================== */

/* ======================================================================
   0) تهيئة Firebase
   ======================================================================
   ⚠️ مهم: استبدل القيم أدناه بمفاتيح مشروعك الفعلية من:
   Firebase Console → Project Settings → General → Your apps → SDK setup
   هذه المفاتيح (apiKey, authDomain...) ليست أسرارًا حساسة بطبيعتها —
   فهي مصممة للظهور في كود العميل (Frontend)، والحماية الحقيقية تأتي من
   Firestore Security Rules وليس من إخفاء هذه القيم.
   ====================================================================== */
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserSessionPersistence
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore,
  collection,
  doc,
  getDoc,
  getDocs,
  addDoc,
  updateDoc,
  deleteDoc,
  setDoc,
  query,
  where,
  orderBy,
  limit,
  increment,
  serverTimestamp,
  onSnapshot
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import {
  getStorage,
  ref as storageRef,
  uploadBytes,
  getDownloadURL,
  deleteObject
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyBWVSDk2xgJQDNk8NwqDY-7akPkENlFqaM",
  authDomain: "dlm-poetry.firebaseapp.com",
  projectId: "dlm-poetry",
  storageBucket: "dlm-poetry.firebasestorage.app",
  messagingSenderId: "4918012230",
  appId: "1:4918012230:web:02a9fbf122011cb4a69d47"
};

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);
const storage = getStorage(firebaseApp);

// الجلسة تنتهي بإغلاق المتصفح (أكثر أمانًا من البقاء مسجلاً للأبد على جهاز مشترك).
// لإبقاء تسجيل الدخول بين الجلسات بدلاً من ذلك، استخدم browserLocalPersistence.
setPersistence(auth, browserSessionPersistence).catch(function(err){
  console.error("Auth persistence error:", err.code);
});

/* ======================================================================
   1) طبقة المصادقة (Authentication Layer)
   ======================================================================
   - لا توجد بيانات اعتماد مكتوبة هنا إطلاقًا.
   - حساب الأدمن الوحيد يُنشأ يدويًا من Firebase Console
     (Authentication → Users → Add user) بإيميل وكلمة مرور من اختيارك.
   - لا توجد صفحة تسجيل عام (Sign Up) عمدًا: فتح التسجيل للعامة يعني
     أن أي زائر يمكنه إنشاء حساب أدمن لنفسه، وهذا غير مقبول أمنيًا.
   ====================================================================== */

let currentUser = null;      // المستخدم المُصادَق حاليًا (null = زائر غير مسجل)
let authReadyResolved = false;

// تسجيل الدخول بالبريد وكلمة المرور — يُستخدم فقط من صفحة /login
function loginWithEmail(email, password){
  return signInWithEmailAndPassword(auth, email, password);
}

// تسجيل خروج آمن: يُنهي الجلسة من Firebase ويُعيد توجيه الزائر لصفحة الدخول
function logoutUser(){
  return signOut(auth);
}

// مراقبة حالة الجلسة في كل وقت: تُستدعى تلقائيًا عند أي تغيّر (دخول/خروج/تحديث صفحة)
onAuthStateChanged(auth, function(user){
  currentUser = user || null;
  authReadyResolved = true;

  // إذا كان المستخدم في صفحة لوحة التحكم وفقد الجلسة (مثلاً انتهت أو سُجِّل خروجه
  // من جهاز آخر)، نعيد توجيهه فورًا لصفحة الدخول لحماية البيانات.
  const activePage = document.querySelector(".page.is-active");
  const isOnAdminPage = activePage && activePage.id === "page-admin";
  if(isOnAdminPage && !currentUser){
    goToPage("login");
    showToast(t("toast_session_expired"), "danger");
  }

  // إعادة رسم أي عنصر واجهة يعتمد على حالة تسجيل الدخول (مثل زر لوحة التحكم في الشريط العلوي)
  refreshAuthDependentUI();

  // تشغيل الموقع لأول مرة فقط بعد أن تتضح حالة المصادقة (لتجنب "ومضة" غير صحيحة للواجهة)
  if(!appBootstrapped){
    appBootstrapped = true;
    bootstrapApp();
  }
});

function isLoggedIn(){ return !!currentUser; }

function refreshAuthDependentUI() {
  const navLoginBtn = document.getElementById("navLoginBtn");
  if (!navLoginBtn) return;

  if (isLoggedIn()) {
    navLoginBtn.style.display = "inline-flex";
    navLoginBtn.setAttribute("data-nav", "admin");
  } else {
    navLoginBtn.style.display = "none";
  }
}

/* ======================================================================
   2) طبقة قاعدة البيانات (Firestore Data Layer)
   ======================================================================
   مجموعات Firestore المستخدمة:
   - poems       : القصائد (منشورة ومسودات، الحقل status يميّز بينها)
   - categories  : التصنيفات
   - quotes      : الاقتباسات المميزة
   - settings    : إعدادات الموقع العامة (مستند واحد بالمعرّف "site")
   - stats       : إحصائيات إضافية مجمّعة (احتياطية لما لا يُحسب من poems مباشرة)
   ====================================================================== */

const COL_POEMS = "poems";
const COL_CATEGORIES = "categories";
const COL_QUOTES = "quotes";
const COL_SETTINGS = "settings";
const COL_STATS = "stats";

// ---------- ذاكرة محلية مؤقتة (Cache) لما يصل من Firestore عبر onSnapshot ----------
// نحتفظ بنسخة محلية حتى تستمر دوال renderXXX القديمة بالعمل بنفس الأسلوب (قراءة من مصفوفة في الذاكرة)
// لكن المصدر الحقيقي الوحيد للبيانات هو Firestore؛ هذه المصفوفات تُحدَّث تلقائيًا بالاستماع المباشر.
let POEMS_CACHE = [];
let CATEGORIES_CACHE = [];
let QUOTES_CACHE = [];

let unsubPoems = null, unsubCategories = null, unsubQuotes = null, unsubAdminPoems = null;
let ADMIN_POEMS_CACHE = []; // كل القصائد (منشورة + مسودات) — تُملأ فقط بعد تسجيل دخول الأدمن

// الاشتراك اللحظي بالقصائد المنشورة فقط (الزوار) — يُعاد استخدامه أيضًا في لوحة التحكم لعرض الكل
function subscribeToPublishedPoems(onChange){
  const q = query(
    collection(db, COL_POEMS),
    where("status", "==", "published"),
    orderBy("date", "desc"),
    limit(50)
  );

  return onSnapshot(
    q,
    function(snap){
      POEMS_CACHE = snap.docs.map(docToPoem);
      onChange(POEMS_CACHE);
    },
    function(err){
      console.error("Firestore poems subscription error:", err.code);
      showToast(t("toast_firestore_error"), "danger");
    }
  );
}

// الاشتراك بكل القصائد (منشورة + مسودات) — يُستخدم فقط داخل لوحة التحكم بعد تسجيل الدخول
function subscribeToAllPoemsAdmin(onChange){
  const q = query(collection(db, COL_POEMS), orderBy("date", "desc"));
  return onSnapshot(q, function(snap){
    onChange(snap.docs.map(docToPoem));
  }, function(err){
    console.error("Firestore admin poems subscription error:", err.code);
    showToast(t("toast_firestore_error"), "danger");
  });
}

function subscribeToCategories(onChange){
  const q = query(collection(db, COL_CATEGORIES), orderBy("name_ar", "asc"));
  return onSnapshot(q, function(snap){
    CATEGORIES_CACHE = snap.docs.map(docToCategory);
    onChange(CATEGORIES_CACHE);
  }, function(err){
    console.error("Firestore categories subscription error:", err.code);
    showToast(t("toast_firestore_error"), "danger");
  });
}

function subscribeToQuotes(onChange){
  const q = query(collection(db, COL_QUOTES), orderBy("createdAt", "desc"));
  return onSnapshot(q, function(snap){
    QUOTES_CACHE = snap.docs.map(docToQuote);
    onChange(QUOTES_CACHE);
  }, function(err){
    console.error("Firestore quotes subscription error:", err.code);
    showToast(t("toast_firestore_error"), "danger");
  });
}

// تحويل مستند Firestore إلى شكل الكائن الذي تتوقعه دوال العرض القديمة (للحفاظ على التوافق الكامل)
function docToPoem(d){
  const data = d.data();
  return {
    id: d.id,
    title_ar: data.title_ar || "",
    title_en: data.title_en || "",
    category: data.category || "",
    date: data.date || "",
    reads: typeof data.reads === "number" ? data.reads : 0,
    body_ar: data.body_ar || "",
    body_en: data.body_en || "",
    coverImageUrl: data.coverImageUrl || "",
    status: data.status || "draft" // "published" | "draft"
  };
}
function docToCategory(d){
  const data = d.data();
  return { id: d.id, name_ar: data.name_ar || "", name_en: data.name_en || "" };
}
function docToQuote(d){
  const data = d.data();
  return { id: d.id, text_ar: data.text_ar || "", text_en: data.text_en || "", source: data.source || "" };
}

// ---------- عمليات الكتابة (Create / Update / Delete) — تتطلب جميعها مستخدمًا مسجلاً، وتُفرَض أيضًا عبر Firestore Rules ----------

async function createPoem(poemData){
  return addDoc(collection(db, COL_POEMS), {
    title_ar: poemData.title_ar,
    title_en: poemData.title_en || "",
    category: poemData.category,
    date: poemData.date,
    body_ar: poemData.body_ar,
    body_en: poemData.body_en || "",
    coverImageUrl: poemData.coverImageUrl || "",
    status: poemData.status || "draft",
    reads: 0,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  });
}

async function updatePoem(poemId, poemData){
  const ref = doc(db, COL_POEMS, poemId);
  return updateDoc(ref, {
    title_ar: poemData.title_ar,
    title_en: poemData.title_en || "",
    category: poemData.category,
    date: poemData.date,
    body_ar: poemData.body_ar,
    body_en: poemData.body_en || "",
    coverImageUrl: poemData.coverImageUrl !== undefined ? poemData.coverImageUrl : "",
    status: poemData.status || "draft",
    updatedAt: serverTimestamp()
  });
}

async function deletePoemById(poemId){
  return deleteDoc(doc(db, COL_POEMS, poemId));
}

// زيادة عداد القراءات بأمان (عملية ذرّية على الخادم، لا تعتمد على قراءة القيمة الحالية أولاً)
async function incrementPoemReads(poemId){
  const ref = doc(db, COL_POEMS, poemId);
  return updateDoc(ref, { reads: increment(1) });
}

async function createCategory(name_ar, name_en){
  return addDoc(collection(db, COL_CATEGORIES), {
    name_ar: name_ar, name_en: name_en || "", createdAt: serverTimestamp()
  });
}
async function updateCategoryById(catId, name_ar, name_en){
  return updateDoc(doc(db, COL_CATEGORIES, catId), { name_ar: name_ar, name_en: name_en || "" });
}
async function deleteCategoryById(catId){
  return deleteDoc(doc(db, COL_CATEGORIES, catId));
}

async function createQuote(text_ar, text_en, source){
  return addDoc(collection(db, COL_QUOTES), {
    text_ar: text_ar, text_en: text_en || "", source: source || "", createdAt: serverTimestamp()
  });
}
async function updateQuoteById(quoteId, text_ar, text_en, source){
  return updateDoc(doc(db, COL_QUOTES, quoteId), { text_ar: text_ar, text_en: text_en || "", source: source || "" });
}
async function deleteQuoteById(quoteId){
  return deleteDoc(doc(db, COL_QUOTES, quoteId));
}

/* ======================================================================
   3) طبقة رفع الصور (Storage Layer) — أغلفة القصائد
   ====================================================================== */
const MAX_COVER_IMAGE_MB = 4;
const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"];

function validateImageFile(file){
  if(!file) return { ok: false, reason: "no_file" };
  if(!ALLOWED_IMAGE_TYPES.includes(file.type)) return { ok: false, reason: "bad_type" };
  if(file.size > MAX_COVER_IMAGE_MB * 1024 * 1024) return { ok: false, reason: "too_large" };
  return { ok: true };
}

// رفع صورة غلاف لقصيدة محددة، يعيد رابط التحميل النهائي
async function uploadCoverImage(poemId, file){
  const safeExt = (file.type === "image/png") ? "png" : (file.type === "image/webp" ? "webp" : "jpg");
  const path = "covers/" + poemId + "/" + Date.now() + "." + safeExt;
  const ref = storageRef(storage, path);
  await uploadBytes(ref, file, { contentType: file.type });
  return getDownloadURL(ref);
}

/* ======================================================================
   4) أدوات مساعدة عامة
   ====================================================================== */
let appBootstrapped = false;

function getCategoryById(id){ return CATEGORIES_CACHE.find(function(c){ return c.id === id; }); }
function getPoemById(id){
  return POEMS_CACHE.find(function(p){ return p.id === id; }) ||
         ADMIN_POEMS_CACHE.find(function(p){ return p.id === id; });
}

function formatDate(dateStr){
  if(!dateStr) return "";
  const d = new Date(dateStr + "T00:00:00");
  if(isNaN(d.getTime())) return dateStr;
  const locale = currentLang === "ar" ? "ar-EG" : "en-US";
  return d.toLocaleDateString(locale, { year: "numeric", month: "long", day: "numeric" });
}

function calcReadTime(text){
  const words = (text || "").trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 120));
}

function formatNumber(num){
  num = Number(num) || 0;
  if(num >= 1000000) return (num/1000000).toFixed(1).replace(/\.0$/,"") + "M";
  if(num >= 1000) return (num/1000).toFixed(1).replace(/\.0$/,"") + "K";
  return String(num);
}

function getPoemTitle(poem){ return currentLang === "en" && poem.title_en ? poem.title_en : poem.title_ar; }
function getPoemBody(poem){ return currentLang === "en" && poem.body_en ? poem.body_en : poem.body_ar; }
function getQuoteText(q){ return currentLang === "en" && q.text_en ? q.text_en : q.text_ar; }
function getCategoryName(cat){ return currentLang === "en" && cat.name_en ? cat.name_en : cat.name_ar; }

// تعقيم النص قبل إدراجه كـ HTML — يمنع XSS عبر عنوان/نص قصيدة يحتوي على وسوم HTML
function escapeHTML(str){
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

// تنظيف نص مُدخَل من المستخدم (إزالة فراغات زائدة، تحديد طول أقصى لمنع إدخال ضخم متعمد)
function sanitizeText(value, maxLen){
  let v = (value || "").toString().trim();
  if(maxLen && v.length > maxLen) v = v.slice(0, maxLen);
  return v;
}

// تحقق أساسي من شكل البريد الإلكتروني قبل إرساله لـ Firebase (تجربة مستخدم أفضل لرسائل الخطأ)
function isValidEmail(email){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function showToast(message, type){
  const wrap = document.getElementById("toastWrap");
  if(!wrap) return;
  const toast = document.createElement("div");
  toast.className = "toast" + (type === "danger" ? " toast-danger" : "");
  toast.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span></span>';
  toast.querySelector("span").textContent = message;
  wrap.appendChild(toast);
  setTimeout(function(){
    toast.classList.add("toast-out");
    setTimeout(function(){ toast.remove(); }, 320);
  }, 2800);
}

function copyTextToClipboard(text){
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).catch(function(){ fallbackCopy(text); });
  }else{
    fallbackCopy(text);
  }
}
function fallbackCopy(text){
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand("copy"); }catch(e){ /* تجاهل */ }
  ta.remove();
}

// ترجمة رموز أخطاء Firebase Auth إلى رسائل مفهومة بدون كشف تفاصيل تقنية حساسة
function firebaseAuthErrorMessage(errorCode){
  const map = {
    ar: {
      "auth/invalid-email": "صيغة البريد الإلكتروني غير صحيحة",
      "auth/user-disabled": "هذا الحساب معطّل",
      "auth/user-not-found": "البريد الإلكتروني أو كلمة المرور غير صحيحة",
      "auth/wrong-password": "البريد الإلكتروني أو كلمة المرور غير صحيحة",
      "auth/invalid-credential": "البريد الإلكتروني أو كلمة المرور غير صحيحة",
      "auth/too-many-requests": "محاولات كثيرة جدًا، حاول مرة أخرى بعد قليل",
      "auth/network-request-failed": "تعذّر الاتصال بالخادم، تحقق من اتصالك بالإنترنت"
    },
    en: {
      "auth/invalid-email": "Invalid email format",
      "auth/user-disabled": "This account has been disabled",
      "auth/user-not-found": "Invalid email or password",
      "auth/wrong-password": "Invalid email or password",
      "auth/invalid-credential": "Invalid email or password",
      "auth/too-many-requests": "Too many attempts, please try again later",
      "auth/network-request-failed": "Could not connect to the server, check your internet connection"
    }
  };
  const dict = map[currentLang] || map.ar;
  return dict[errorCode] || (currentLang === "ar" ? "حدث خطأ غير متوقع، حاول مرة أخرى" : "An unexpected error occurred, please try again");
}

/* ======================================================================
   5) نظام الترجمة (i18n)
   ====================================================================== */
const I18N = {
  ar: {
    brand_ar: "دلم",
    nav_home: "الرئيسية", nav_poems: "القصائد", nav_categories: "التصنيفات",
    nav_quotes: "الاقتباسات", nav_about: "عن الشاعر", nav_login: "لوحة التحكم",
    search_placeholder: "ابحث عن قصيدة، عبارة، أو تصنيف...",
    search_close: "إغلاق", search_hint: "ابدأ الكتابة لعرض النتائج...",
    search_no_results: "لا توجد نتائج مطابقة لبحثك",
    hero_tagline: "لستُ شاعرًا... أنا ترجمانُ شعور.",
    hero_cta_primary: "اقرأ القصائد", hero_cta_secondary: "عن الشاعر",
    scroll_hint: "انزل للأسفل",
    eyebrow_latest: "حديثًا", title_latest: "آخر القصائد",
    eyebrow_mostread: "الأكثر صدى", title_mostread: "الأكثر قراءة",
    eyebrow_quotes: "من بين السطور", title_quotes: "اقتباسات مميزة",
    eyebrow_categories: "استكشف", title_categories: "التصنيفات",
    eyebrow_related: "قصائد قريبة من هذا الشعور", title_related: "قد يعجبك أيضًا",
    eyebrow_archive: "ديوان دلم", title_archive: "كل القصائد",
    archive_subtitle: "رحلة كاملة عبر كل ما كُتب من شعور وحروف.",
    categories_subtitle: "كل تصنيف نافذة على شعور مختلف.",
    quotes_subtitle: "جُمل قصيرة، أثرها طويل.",
    eyebrow_about: "سيرة بالكلمات", title_about: "عن دلم",
    about_text: "دلم ليس اسمًا، بل محاولة. محاولة لترجمة ما لا تسعه الكلمات العادية، ولإعطاء الشعور شكلاً يُقرأ بعد أن كان يُعاش وحده في صمت. منذ السطر الأول، لم يكتب دلم القصيدة، بل سمح للقصيدة أن تكتبه. كل نص هنا هو شهادة على لحظة صدق، ومحطة من رحلة لا تنتهي بين القلب واللغة.",
    about_quote: "لستُ شاعرًا... أنا ترجمانُ شعور.",
    view_all: "عرض الكل",
    filter_all: "الكل",
    read_time_unit: "د قراءة", reads_unit: "قراءة",
    share_label: "شارك القصيدة:", copied_label: "تم النسخ",
    empty_poems_title: "لا توجد قصائد هنا الآن", empty_poems_sub: "جرّب تصنيفًا آخر أو كلمة بحث مختلفة.",
    empty_no_poems: "لا توجد قصائد بعد",
    loading_label: "جارٍ التحميل...",
    login_title: "تسجيل الدخول", login_sub: "للوصول إلى لوحة تحكم دلم",
    login_email: "البريد الإلكتروني", login_password: "كلمة المرور", login_submit: "دخول",
    login_submitting: "جارٍ تسجيل الدخول...",
    login_error_required: "هذا الحقل مطلوب", login_error_email: "أدخل بريدًا إلكترونيًا صحيحًا",
    login_success_toast: "تم تسجيل الدخول بنجاح، أهلًا بك",
    toast_session_expired: "انتهت الجلسة، يرجى تسجيل الدخول من جديد",
    toast_firestore_error: "تعذّر الاتصال بقاعدة البيانات، حاول مرة أخرى",
    toast_unauthorized: "هذه الصفحة تتطلب تسجيل دخول الأدمن",
    admin_user_role: "مدير المحتوى",
    admin_nav_stats: "الإحصائيات", admin_nav_poems: "القصائد",
    admin_nav_categories: "التصنيفات", admin_nav_quotes: "الاقتباسات", admin_logout: "تسجيل الخروج",
    stats_title: "نظرة عامة", stats_sub: "ملخص أداء ديوان دلم لحظة بلحظة",
    stat_total_poems: "عدد القصائد", stat_total_reads: "عدد القراءات",
    stat_total_categories: "عدد التصنيفات", stat_total_quotes: "عدد الاقتباسات",
    stats_most_read: "الأكثر قراءة", stats_latest: "أحدث القصائد المنشورة",
    admin_poems_title: "إدارة القصائد", admin_poems_sub: "أضف، عدّل، أو حذف قصائد الديوان",
    admin_add_poem: "إضافة قصيدة", admin_search_placeholder: "بحث في القصائد...",
    th_title: "العنوان", th_category: "التصنيف", th_date: "تاريخ النشر", th_reads: "القراءات", th_status: "الحالة", th_actions: "إجراءات",
    status_published: "منشورة", status_draft: "مسودة",
    admin_categories_title: "إدارة التصنيفات", admin_categories_sub: "صنّف قصائدك حسب الشعور أو الموضوع",
    admin_add_category: "إضافة تصنيف", th_category_name: "اسم التصنيف", th_poems_count: "عدد القصائد",
    admin_quotes_title: "إدارة الاقتباسات", admin_quotes_sub: "جُمل مميزة تُعرض في الصفحة الرئيسية",
    admin_add_quote: "إضافة اقتباس", th_quote_text: "النص", th_source: "المصدر",
    modal_add_poem_title: "إضافة قصيدة جديدة", modal_edit_poem_title: "تعديل القصيدة",
    field_poem_title: "عنوان القصيدة", field_poem_category: "التصنيف", field_poem_date: "تاريخ النشر",
    field_poem_body: "نص القصيدة الكامل", field_poem_body_hint: "سيُحتسب وقت القراءة تلقائيًا حسب عدد الكلمات.",
    field_poem_cover: "صورة الغلاف (اختياري)", field_poem_cover_hint: "JPG أو PNG أو WEBP، حتى 4MB.",
    field_poem_status: "حالة النشر",
    btn_cancel: "إلغاء", btn_save_draft: "حفظ كمسودة", btn_publish: "نشر القصيدة", btn_save_generic: "حفظ", btn_delete: "حذف نهائي",
    btn_uploading: "جارٍ رفع الصورة...",
    modal_add_category_title: "إضافة تصنيف جديد", modal_edit_category_title: "تعديل التصنيف",
    field_category_name: "اسم التصنيف",
    modal_add_quote_title: "إضافة اقتباس جديد", modal_edit_quote_title: "تعديل الاقتباس",
    field_quote_text: "نص الاقتباس", field_quote_source: "المصدر (اسم القصيدة - اختياري)",
    confirm_delete_title: "تأكيد الحذف", confirm_delete_sub: "هذا الإجراء لا يمكن التراجع عنه. هل أنت متأكد؟",
    toast_poem_added: "تمت إضافة القصيدة بنجاح", toast_poem_updated: "تم تحديث القصيدة بنجاح",
    toast_poem_deleted: "تم حذف القصيدة", toast_category_added: "تمت إضافة التصنيف",
    toast_category_updated: "تم تحديث التصنيف", toast_category_deleted: "تم حذف التصنيف",
    toast_category_in_use: "لا يمكن حذف تصنيف مستخدم في قصائد",
    toast_quote_added: "تمت إضافة الاقتباس", toast_quote_updated: "تم تحديث الاقتباس",
    toast_quote_deleted: "تم حذف الاقتباس", toast_link_copied: "تم نسخ رابط القصيدة",
    toast_logged_out: "تم تسجيل الخروج", toast_newsletter: "تم تسجيل بريدك في النشرة، شكرًا لك",
    toast_image_invalid_type: "الصورة يجب أن تكون JPG أو PNG أو WEBP",
    toast_image_too_large: "حجم الصورة يجب ألا يتجاوز 4MB",
    footer_about_text: "دلم مساحة لترجمة الشعور إلى كلمات، وللكلمات أن تجد من يفهمها. كل قصيدة هنا رسالة، وكل قارئ شريك في المعنى.",
    footer_explore: "استكشف", footer_more: "روابط", footer_contact: "تواصل معنا", footer_privacy: "سياسة الخصوصية",
    footer_newsletter: "النشرة البريدية", footer_email_placeholder: "بريدك الإلكتروني", footer_subscribe: "اشترك",
    footer_copyright: "© 2026 دلم | DLM — جميع الحقوق محفوظة.", footer_tagline: "لستُ شاعرًا... أنا ترجمانُ شعور.",
    edit_action: "تعديل", delete_action: "حذف", view_action: "عرض"
  },
  en: {
    brand_ar: "DLM",
    nav_home: "Home", nav_poems: "Poems", nav_categories: "Categories",
    nav_quotes: "Quotes", nav_about: "About", nav_login: "Dashboard",
    search_placeholder: "Search for a poem, phrase, or category...",
    search_close: "Close", search_hint: "Start typing to see results...",
    search_no_results: "No results match your search",
    hero_tagline: "I'm not a poet... I'm a translator of feeling.",
    hero_cta_primary: "Read the Poems", hero_cta_secondary: "About the Poet",
    scroll_hint: "Scroll down",
    eyebrow_latest: "Fresh ink", title_latest: "Latest Poems",
    eyebrow_mostread: "Most resonant", title_mostread: "Most Read",
    eyebrow_quotes: "Between the lines", title_quotes: "Featured Quotes",
    eyebrow_categories: "Explore", title_categories: "Categories",
    eyebrow_related: "Poems close to this feeling", title_related: "You May Also Like",
    eyebrow_archive: "DLM's Anthology", title_archive: "All Poems",
    archive_subtitle: "A complete journey through every feeling ever written.",
    categories_subtitle: "Each category is a window into a different feeling.",
    quotes_subtitle: "Short sentences, lasting echoes.",
    eyebrow_about: "A biography in words", title_about: "About DLM",
    about_text: "DLM is not a name, but an attempt — an attempt to translate what ordinary words cannot hold, and to give feeling a form that can be read after living alone in silence. From the very first line, DLM did not write the poem; the poem was allowed to write him. Every text here is testimony to a moment of honesty, a stop on an endless journey between heart and language.",
    about_quote: "I'm not a poet... I'm a translator of feeling.",
    view_all: "View all",
    filter_all: "All",
    read_time_unit: "min read", reads_unit: "reads",
    share_label: "Share this poem:", copied_label: "Copied",
    empty_poems_title: "No poems here yet", empty_poems_sub: "Try another category or a different search term.",
    empty_no_poems: "No poems yet",
    loading_label: "Loading...",
    login_title: "Sign In", login_sub: "Access the DLM dashboard",
    login_email: "Email", login_password: "Password", login_submit: "Sign In",
    login_submitting: "Signing in...",
    login_error_required: "This field is required", login_error_email: "Enter a valid email address",
    login_success_toast: "Signed in successfully, welcome back",
    toast_session_expired: "Session expired, please sign in again",
    toast_firestore_error: "Could not connect to the database, please try again",
    toast_unauthorized: "This page requires admin sign-in",
    admin_user_role: "Content Manager",
    admin_nav_stats: "Statistics", admin_nav_poems: "Poems",
    admin_nav_categories: "Categories", admin_nav_quotes: "Quotes", admin_logout: "Log Out",
    stats_title: "Overview", stats_sub: "A live summary of DLM's anthology performance",
    stat_total_poems: "Total Poems", stat_total_reads: "Total Reads",
    stat_total_categories: "Total Categories", stat_total_quotes: "Total Quotes",
    stats_most_read: "Most Read", stats_latest: "Latest Published",
    admin_poems_title: "Manage Poems", admin_poems_sub: "Add, edit, or delete poems in the anthology",
    admin_add_poem: "Add Poem", admin_search_placeholder: "Search poems...",
    th_title: "Title", th_category: "Category", th_date: "Published", th_reads: "Reads", th_status: "Status", th_actions: "Actions",
    status_published: "Published", status_draft: "Draft",
    admin_categories_title: "Manage Categories", admin_categories_sub: "Sort poems by feeling or theme",
    admin_add_category: "Add Category", th_category_name: "Category Name", th_poems_count: "Poems Count",
    admin_quotes_title: "Manage Quotes", admin_quotes_sub: "Featured lines shown on the homepage",
    admin_add_quote: "Add Quote", th_quote_text: "Text", th_source: "Source",
    modal_add_poem_title: "Add New Poem", modal_edit_poem_title: "Edit Poem",
    field_poem_title: "Poem Title", field_poem_category: "Category", field_poem_date: "Published Date",
    field_poem_body: "Full Poem Text", field_poem_body_hint: "Reading time is calculated automatically by word count.",
    field_poem_cover: "Cover Image (optional)", field_poem_cover_hint: "JPG, PNG, or WEBP, up to 4MB.",
    field_poem_status: "Publish Status",
    btn_cancel: "Cancel", btn_save_draft: "Save as Draft", btn_publish: "Publish Poem", btn_save_generic: "Save", btn_delete: "Delete Permanently",
    btn_uploading: "Uploading image...",
    modal_add_category_title: "Add New Category", modal_edit_category_title: "Edit Category",
    field_category_name: "Category Name",
    modal_add_quote_title: "Add New Quote", modal_edit_quote_title: "Edit Quote",
    field_quote_text: "Quote Text", field_quote_source: "Source (poem name - optional)",
    confirm_delete_title: "Confirm Deletion", confirm_delete_sub: "This action cannot be undone. Are you sure?",
    toast_poem_added: "Poem added successfully", toast_poem_updated: "Poem updated successfully",
    toast_poem_deleted: "Poem deleted", toast_category_added: "Category added",
    toast_category_updated: "Category updated", toast_category_deleted: "Category deleted",
    toast_category_in_use: "Cannot delete a category used by poems",
    toast_quote_added: "Quote added", toast_quote_updated: "Quote updated",
    toast_quote_deleted: "Quote deleted", toast_link_copied: "Poem link copied",
    toast_logged_out: "Logged out", toast_newsletter: "Your email has been subscribed, thank you",
    toast_image_invalid_type: "Image must be JPG, PNG, or WEBP",
    toast_image_too_large: "Image size must not exceed 4MB",
    footer_about_text: "DLM is a space for translating feeling into words, and for words to find someone who understands them. Every poem here is a message, and every reader is a partner in meaning.",
    footer_explore: "Explore", footer_more: "Links", footer_contact: "Contact Us", footer_privacy: "Privacy Policy",
    footer_newsletter: "Newsletter", footer_email_placeholder: "Your email address", footer_subscribe: "Subscribe",
    footer_copyright: "© 2026 DLM — All rights reserved.", footer_tagline: "I'm not a poet... I'm a translator of feeling.",
    edit_action: "Edit", delete_action: "Delete", view_action: "View"
  }
};

let currentLang = "ar";

function t(key){
  return (I18N[currentLang] && I18N[currentLang][key]) || (I18N.ar[key] || key);
}

function applyTranslations(){
  document.documentElement.lang = currentLang;
  document.documentElement.dir = currentLang === "ar" ? "rtl" : "ltr";

  document.querySelectorAll("[data-i18n]").forEach(function(el){
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(function(el){
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
  });
  document.querySelectorAll(".lang-switch button").forEach(function(btn){
    btn.classList.toggle("active", btn.getAttribute("data-lang") === currentLang);
  });

  renderHomeContent();
  renderArchivePage(currentArchiveFilter, currentSearchTerm);
  renderCategoriesPage();
  renderQuotesPage();
  if(currentPoemId){ renderPoemPage(currentPoemId); }
  if(isLoggedIn()){
    renderAdminStats();
    renderAdminPoemsTable();
    renderAdminCategoriesTable();
    renderAdminQuotesTable();
    refreshPoemFormCategoryOptions();
  }
  startHeroTaglineAnimation();
}

/* ======================================================================
   6) نظام التوجيه بين الصفحات (Router)
   ====================================================================== */
let currentArchiveFilter = "all";
let currentSearchTerm = "";
let currentPoemId = null;
let pendingDeleteAction = null;

function goToPage(pageName, opts){
  opts = opts || {};

  // حماية حقيقية للوحة التحكم: لا اعتماد على متغير محلي، بل على حالة Firebase Auth الفعلية
  if(pageName === "admin" && !isLoggedIn()){
    showToast(t("toast_unauthorized"), "danger");
    pageName = "login";
  }

  document.querySelectorAll(".page").forEach(function(p){ p.classList.remove("is-active"); });
  const target = document.getElementById("page-" + pageName);
  if(target) target.classList.add("is-active");

  const footer = document.getElementById("siteFooter");
  if(footer) footer.style.display = (pageName === "login" || pageName === "admin") ? "none" : "";

  document.querySelectorAll(".nav-links a, .mobile-menu a").forEach(function(a){
    a.classList.toggle("active", a.getAttribute("data-nav") === pageName);
  });

  closeMobileMenu();
  closeSearchModal();
  window.scrollTo({ top: 0 });

  if(pageName === "poem" && opts.poemId){
    currentPoemId = opts.poemId;
    renderPoemPage(opts.poemId);
  }
  if(pageName === "archive"){
    currentArchiveFilter = opts.filter || "all";
    currentSearchTerm = opts.search || "";
    renderArchivePage(currentArchiveFilter, currentSearchTerm);
  }
  if(pageName === "login"){
    const form = document.getElementById("loginForm");
    if(form){ form.reset(); clearFieldErrors(form); }
  }
  if(pageName === "admin"){
    startAdminSubscriptions();
  }
}

document.addEventListener("click", function(e){
  const navEl = e.target.closest("[data-nav]");
  if(!navEl) return;
  e.preventDefault();
  const pageName = navEl.getAttribute("data-nav");

  if(pageName === "login" && isLoggedIn()){
    goToPage("admin");
    return;
  }
  if(pageName === "archive"){
    goToPage("archive", { filter: navEl.getAttribute("data-archive-filter") || "all", search: "" });
    return;
  }
  goToPage(pageName);
});

/* ======================================================================
   7) عرض محتوى الصفحة الرئيسية
   ====================================================================== */
function buildPoemCardHTML(poem){
  const cat = getCategoryById(poem.category);
  const catName = cat ? getCategoryName(cat) : "";
  const excerpt = getPoemBody(poem).split("\n").filter(Boolean).slice(0,3).join(" ");
  const coverStyle = poem.coverImageUrl
    ? ' style="background-image:linear-gradient(180deg, rgba(10,10,10,.15), rgba(10,10,10,.85)), url(\'' + escapeHTML(poem.coverImageUrl) + '\'); background-size:cover; background-position:center;"'
    : '';
  return (
    '<article class="poem-card" data-poem-id="' + poem.id + '" tabindex="0" role="button" aria-label="' + escapeHTML(getPoemTitle(poem)) + '"' + coverStyle + '>' +
      '<div class="poem-card-top">' +
        '<span class="poem-tag">' + escapeHTML(catName) + '</span>' +
        '<span class="poem-date">' + formatDate(poem.date) + '</span>' +
      '</div>' +
      '<h3>' + escapeHTML(getPoemTitle(poem)) + '</h3>' +
      '<p class="poem-excerpt">' + escapeHTML(excerpt) + '</p>' +
      '<div class="poem-card-foot">' +
        '<span class="stat"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>' + formatNumber(poem.reads) + ' ' + t("reads_unit") + '</span>' +
        '<span class="stat"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>' + calcReadTime(getPoemBody(poem)) + ' ' + t("read_time_unit") + '</span>' +
      '</div>' +
    '</article>'
  );
}

function buildMostReadRowHTML(poem, rank){
  return (
    '<div class="poems-list-row" data-poem-id="' + poem.id + '" tabindex="0" role="button" aria-label="' + escapeHTML(getPoemTitle(poem)) + '">' +
      '<span class="rank">' + String(rank).padStart(2,"0") + '</span>' +
      '<div class="info">' +
        '<h4>' + escapeHTML(getPoemTitle(poem)) + '</h4>' +
        '<p>' + formatDate(poem.date) + '</p>' +
      '</div>' +
      '<span class="reads"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>' + formatNumber(poem.reads) + '</span>' +
    '</div>'
  );
}

function buildQuoteCardHTML(q){
  return (
    '<div class="quote-card">' +
      '<span class="quote-mark">&ldquo;</span>' +
      '<p class="quote-text">' + escapeHTML(getQuoteText(q)) + '</p>' +
      '<span class="quote-source">' + escapeHTML(q.source || "") + '</span>' +
      '<div class="quote-actions">' +
        '<button type="button" class="quote-copy-btn" data-quote-text="' + escapeHTML(getQuoteText(q)) + '">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>' +
          '<span>' + (currentLang === "ar" ? "نسخ" : "Copy") + '</span>' +
        '</button>' +
      '</div>' +
    '</div>'
  );
}

const CATEGORY_ICONS = [
  '<path d="M12 21s-7-4.5-9.5-9C0.5 7.5 3 3 7 3c2 0 4 1 5 3 1-2 3-3 5-3 4 0 6.5 4.5 4.5 9-2.5 4.5-9.5 9-9.5 9z"/>',
  '<path d="M3 12h4l3-9 4 18 3-9h4"/>',
  '<path d="M12 2v20M2 12h20"/>',
  '<path d="M3 21V10l9-7 9 7v11h-6v-7H9v7z"/>',
  '<path d="M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>',
  '<path d="M12 2v8M5.6 5.6l1.4 1.4M18.4 5.6l-1.4 1.4M2 14h2M20 14h2M7 21h10M12 14a4 4 0 0 0 4-4 4 4 0 1 0-8 0 4 4 0 0 0 4 4z"/>'
];
function getCategoryIcon(index){ return CATEGORY_ICONS[index % CATEGORY_ICONS.length]; }

function buildCategoryCardHTML(cat, index){
  const count = POEMS_CACHE.filter(function(p){ return p.category === cat.id; }).length;
  return (
    '<a href="#" class="cat-card" data-nav="archive" data-archive-filter="' + cat.id + '">' +
      '<div class="cat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">' + getCategoryIcon(index) + '</svg></div>' +
      '<h4>' + escapeHTML(getCategoryName(cat)) + '</h4>' +
      '<span>' + count + ' ' + (currentLang === "ar" ? "قصيدة" : "poems") + '</span>' +
    '</a>'
  );
}

// حالة تحميل بسيطة (Skeleton/Empty) أثناء وصول أول دفعة من Firestore
function buildLoadingPlaceholderHTML(){
  return '<div class="empty-state" style="grid-column:1/-1;"><p style="color:var(--muted);">' + t("loading_label") + '</p></div>';
}

let firstPoemsSnapshotArrived = false;

function renderHomeContent(){
  const latestGrid = document.getElementById("latestPoemsGrid");
  const mostReadList = document.getElementById("mostReadList");

  if(!firstPoemsSnapshotArrived){
    latestGrid.innerHTML = buildLoadingPlaceholderHTML();
    mostReadList.innerHTML = "";
  }else{
    const latest = POEMS_CACHE.slice().sort(function(a,b){ return new Date(b.date) - new Date(a.date); }).slice(0,3);
    latestGrid.innerHTML = latest.length ? latest.map(buildPoemCardHTML).join("") :
      '<div class="empty-state" style="grid-column:1/-1;"><h4>' + t("empty_poems_title") + '</h4></div>';

    const mostRead = POEMS_CACHE.slice().sort(function(a,b){ return b.reads - a.reads; }).slice(0,5);
    mostReadList.innerHTML = mostRead.map(function(p,i){ return buildMostReadRowHTML(p, i+1); }).join("");
  }

  document.getElementById("homeQuotesTrack").innerHTML = QUOTES_CACHE.slice(0,3).map(buildQuoteCardHTML).join("");
  document.getElementById("homeCatsGrid").innerHTML = CATEGORIES_CACHE.slice(0,4).map(function(c,i){ return buildCategoryCardHTML(c,i); }).join("");
}

/* ======================================================================
   تأثير "الحبر يُكتب" لعبارة الهيرو — نسخة مُصحَّحة لدعم العربية بشكل سليم
   ======================================================================
   المشكلة في النسخة السابقة: كانت تُقسّم النص حرفًا بحرف (split("")) وتضع
   كل حرف في <span> منفصل بـ display:inline-block. هذا يكسر "تشكيل الحروف"
   العربي (Arabic text shaping) لأن المتصفح يحتاج رؤية الحروف متجاورة في نفس
   العقدة النصية ليقرر الشكل الصحيح لكل حرف (بداية/وسط/نهاية/منفصل). فصلها
   إلى عناصر DOM مستقلة يجعل كل حرف يُعرض في "شكله المنفصل" دومًا، فتظهر
   الكلمة مفككة.

   الحل: لا نفصل الحروف عن بعضها في DOM إطلاقًا. النص الكامل يبقى عقدة
   نصية واحدة متصلة (لتشكيل عربي طبيعي 100%)، والتأثير البصري "الكتابة
   التدريجية" يتم عبر كشف تدريجي لعرض الحاوية (clip-path) بمحاذاة تناسب
   اتجاه RTL، بدل تفكيك الحروف. هذا يعمل بنفس الجودة على العربية والإنجليزية
   وعلى الموبايل والديسكتوب دون أي حرف مكسور.
   ====================================================================== */
let heroTaglineRAF = null;
let heroTaglineTimeout = null;

function startHeroTaglineAnimation(){
  const wrap = document.getElementById("heroTaglineWrap");
  const el = document.getElementById("heroTagline");
  if(!el || !wrap) return;

  if(heroTaglineRAF) cancelAnimationFrame(heroTaglineRAF);
  if(heroTaglineTimeout) clearTimeout(heroTaglineTimeout);

  const text = t("hero_tagline");
  const isRTL = currentLang === "ar";

  // النص الكامل يُكتب كعقدة نصية واحدة متصلة — هذا هو أساس الحل لمشكلة تفكك الحروف
  el.textContent = text;
  el.style.direction = isRTL ? "rtl" : "ltr";
  el.style.unicodeBidi = "plaintext";

  // تأثير الكتابة: كشف تدريجي لعرض العنصر عبر clip-path من جهة البداية المنطقية للنص
  // (من اليمين في RTL، ومن اليسار في LTR)، فيبدو كأن الحبر "يُكتب" دون كسر تشكيل الحروف.
  el.style.clipPath = isRTL ? "inset(0 0 0 100%)" : "inset(0 100% 0 0)";
  el.style.opacity = "1";
  el.style.filter = "none";

  const totalDurationMs = Math.min(2600, Math.max(1100, text.length * 55));
  const startTime = performance.now();

  function step(now){
    const progress = Math.min(1, (now - startTime) / totalDurationMs);
    // تسهيل حركة طبيعي (ease-out) ليبدأ سريعًا وينتهي بنعومة كحركة يد فعلية
    const eased = 1 - Math.pow(1 - progress, 3);
    const revealPercent = eased * 100;

    el.style.clipPath = isRTL
      ? "inset(0 0 0 " + (100 - revealPercent) + "%)"
      : "inset(0 " + (100 - revealPercent) + "% 0 0)";

    if(progress < 1){
      heroTaglineRAF = requestAnimationFrame(step);
    }else{
      el.style.clipPath = "none"; // إزالة القص بعد الانتهاء لتفادي أي تأثير على التحديد/النسخ
    }
  }
  heroTaglineRAF = requestAnimationFrame(step);
}

document.addEventListener("click", function(e){
  const card = e.target.closest("[data-poem-id]");
  if(card && !e.target.closest("[data-nav]")){
    openPoem(card.getAttribute("data-poem-id"));
  }
  const copyBtn = e.target.closest(".quote-copy-btn");
  if(copyBtn){
    copyTextToClipboard(copyBtn.getAttribute("data-quote-text"));
    showToast(currentLang === "ar" ? "تم نسخ الاقتباس" : "Quote copied");
  }
});
document.addEventListener("keydown", function(e){
  if(e.key !== "Enter" && e.key !== " ") return;
  const card = e.target.closest("[data-poem-id]");
  if(card){ e.preventDefault(); openPoem(card.getAttribute("data-poem-id")); }
});

async function openPoem(poemId){
  const poem = getPoemById(poemId);
  if(!poem) return;
  goToPage("poem", { poemId: poemId });
  // زيادة عداد القراءات بعملية ذرّية على الخادم (لا تعديل محلي مباشر على القيمة)
  try{ await incrementPoemReads(poemId); }
  catch(err){ console.error("incrementPoemReads error:", err.code || err.message); }
}

/* ======================================================================
   8) صفحة القصيدة الفردية + المشاركة
   ====================================================================== */
function renderPoemPage(poemId){
  const poem = getPoemById(poemId);
  if(!poem){
    document.getElementById("poemPageTitle").textContent = currentLang === "ar" ? "القصيدة غير موجودة" : "Poem not found";
    document.getElementById("poemPageBody").textContent = "";
    document.getElementById("relatedPoemsGrid").innerHTML = "";
    return;
  }
  const cat = getCategoryById(poem.category);
  document.getElementById("poemBreadcrumbTitle").textContent = getPoemTitle(poem);
  document.getElementById("poemPageCat").textContent = cat ? getCategoryName(cat) : "";
  document.getElementById("poemPageTitle").textContent = getPoemTitle(poem);
  document.getElementById("poemPageDate").textContent = formatDate(poem.date);
  document.getElementById("poemPageReadTime").textContent = calcReadTime(getPoemBody(poem)) + " " + t("read_time_unit");
  document.getElementById("poemPageReads").textContent = formatNumber(poem.reads) + " " + t("reads_unit");
  document.getElementById("poemPageBody").textContent = getPoemBody(poem);

  const related = POEMS_CACHE.filter(function(p){ return p.category === poem.category && p.id !== poem.id; }).slice(0,3);
  const fallback = related.length ? related : POEMS_CACHE.filter(function(p){ return p.id !== poem.id; }).slice(0,3);
  document.getElementById("relatedPoemsGrid").innerHTML = fallback.map(buildPoemCardHTML).join("");

  resetCopyLinkButton();
}

function getPoemShareURL(poemId){
  const base = window.location.href.split("#")[0].split("?")[0];
  return base + "?poem=" + encodeURIComponent(poemId);
}
function resetCopyLinkButton(){
  const btn = document.getElementById("copyLinkBtn");
  if(btn) btn.classList.remove("copied");
}

document.getElementById("shareX").addEventListener("click", function(){
  const poem = getPoemById(currentPoemId); if(!poem) return;
  const url = getPoemShareURL(currentPoemId);
  const text = getPoemTitle(poem) + " — DLM | دلم";
  window.open("https://twitter.com/intent/tweet?text=" + encodeURIComponent(text) + "&url=" + encodeURIComponent(url), "_blank", "noopener,noreferrer,width=600,height=500");
});
document.getElementById("shareWhatsapp").addEventListener("click", function(){
  const poem = getPoemById(currentPoemId); if(!poem) return;
  const url = getPoemShareURL(currentPoemId);
  const text = getPoemTitle(poem) + " — DLM | دلم\n" + url;
  window.open("https://api.whatsapp.com/send?text=" + encodeURIComponent(text), "_blank", "noopener,noreferrer");
});
document.getElementById("shareTelegram").addEventListener("click", function(){
  const poem = getPoemById(currentPoemId); if(!poem) return;
  const url = getPoemShareURL(currentPoemId);
  const text = getPoemTitle(poem) + " — DLM | دلم";
  window.open("https://t.me/share/url?url=" + encodeURIComponent(url) + "&text=" + encodeURIComponent(text), "_blank", "noopener,noreferrer,width=600,height=500");
});
document.getElementById("shareFacebook").addEventListener("click", function(){
  const url = getPoemShareURL(currentPoemId);
  window.open("https://www.facebook.com/sharer/sharer.php?u=" + encodeURIComponent(url), "_blank", "noopener,noreferrer,width=600,height=500");
});
document.getElementById("copyLinkBtn").addEventListener("click", function(){
  const url = getPoemShareURL(currentPoemId);
  copyTextToClipboard(url);
  this.classList.add("copied");
  showToast(t("toast_link_copied"));
  setTimeout(function(){ document.getElementById("copyLinkBtn").classList.remove("copied"); }, 2000);
});

/* ======================================================================
   9) صفحة الأرشيف / التصنيفات / الاقتباسات / البحث
   ====================================================================== */
function renderArchiveFilters(activeFilter){
  const wrap = document.getElementById("archiveFilters");
  let html = '<button type="button" class="filter-chip' + (activeFilter === "all" ? " active" : "") + '" data-filter="all">' + t("filter_all") + '</button>';
  CATEGORIES_CACHE.forEach(function(cat){
    html += '<button type="button" class="filter-chip' + (activeFilter === cat.id ? " active" : "") + '" data-filter="' + cat.id + '">' + escapeHTML(getCategoryName(cat)) + '</button>';
  });
  wrap.innerHTML = html;
}

function renderArchivePage(filter, searchTerm){
  filter = filter || "all";
  searchTerm = (searchTerm || "").trim().toLowerCase();
  renderArchiveFilters(filter);

  let list = POEMS_CACHE.slice();
  if(filter !== "all"){ list = list.filter(function(p){ return p.category === filter; }); }
  if(searchTerm){
    list = list.filter(function(p){
      const hay = (getPoemTitle(p) + " " + getPoemBody(p)).toLowerCase();
      return hay.indexOf(searchTerm) !== -1;
    });
  }
  list.sort(function(a,b){ return new Date(b.date) - new Date(a.date); });

  const grid = document.getElementById("archiveGrid");
  const empty = document.getElementById("archiveEmpty");
  if(list.length === 0){
    grid.innerHTML = ""; empty.style.display = "block";
  }else{
    empty.style.display = "none";
    grid.innerHTML = list.map(buildPoemCardHTML).join("");
  }

  const titleEl = document.getElementById("archiveTitle");
  const subEl = document.getElementById("archiveSubtitle");
  if(searchTerm){
    titleEl.textContent = currentLang === "ar" ? ('نتائج البحث: "' + searchTerm + '"') : ('Search results: "' + searchTerm + '"');
    subEl.textContent = list.length + (currentLang === "ar" ? " نتيجة" : " results found");
  }else if(filter !== "all"){
    const cat = getCategoryById(filter);
    titleEl.textContent = cat ? getCategoryName(cat) : t("title_archive");
    subEl.textContent = t("archive_subtitle");
  }else{
    titleEl.textContent = t("title_archive");
    subEl.textContent = t("archive_subtitle");
  }
}

document.getElementById("archiveFilters").addEventListener("click", function(e){
  const chip = e.target.closest(".filter-chip");
  if(!chip) return;
  currentArchiveFilter = chip.getAttribute("data-filter");
  currentSearchTerm = "";
  renderArchivePage(currentArchiveFilter, "");
});

function renderCategoriesPage(){
  document.getElementById("categoriesPageGrid").innerHTML = CATEGORIES_CACHE.map(function(c,i){ return buildCategoryCardHTML(c,i); }).join("");
}
function renderQuotesPage(){
  document.getElementById("quotesPageGrid").innerHTML = QUOTES_CACHE.map(buildQuoteCardHTML).join("");
}

// ---------- البحث السريع (مودال) ----------
const searchModal = document.getElementById("searchModal");
const searchInput = document.getElementById("searchInput");

function openSearchModal(){
  searchModal.classList.add("is-open");
  setTimeout(function(){ searchInput.focus(); }, 150);
  renderSearchResults("");
}
function closeSearchModal(){
  searchModal.classList.remove("is-open");
  searchInput.value = "";
}
document.getElementById("searchTrigger").addEventListener("click", openSearchModal);
document.getElementById("searchCloseBtn").addEventListener("click", closeSearchModal);
searchModal.addEventListener("click", function(e){ if(e.target === searchModal) closeSearchModal(); });
document.addEventListener("keydown", function(e){
  if(e.key === "Escape"){ closeSearchModal(); closeAllModals(); }
  if((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k"){
    e.preventDefault();
    openSearchModal();
  }
});

function renderSearchResults(term){
  const resultsEl = document.getElementById("searchResults");
  term = term.trim().toLowerCase();
  if(!term){
    resultsEl.innerHTML = '<div class="search-empty">' + t("search_hint") + '</div>';
    return;
  }
  const matches = POEMS_CACHE.filter(function(p){
    const cat = getCategoryById(p.category);
    const hay = (getPoemTitle(p) + " " + getPoemBody(p) + " " + (cat ? getCategoryName(cat) : "")).toLowerCase();
    return hay.indexOf(term) !== -1;
  }).slice(0,8);

  if(matches.length === 0){
    resultsEl.innerHTML = '<div class="search-empty">' + t("search_no_results") + '</div>';
    return;
  }
  resultsEl.innerHTML = matches.map(function(p){
    const cat = getCategoryById(p.category);
    return (
      '<div class="search-result-item" data-poem-id="' + p.id + '" tabindex="0" role="button">' +
        '<span class="sr-title">' + escapeHTML(getPoemTitle(p)) + '</span>' +
        '<span class="sr-meta">' + (cat ? escapeHTML(getCategoryName(cat)) : "") + ' • ' + formatDate(p.date) + '</span>' +
      '</div>'
    );
  }).join("");
}
searchInput.addEventListener("input", function(){ renderSearchResults(this.value); });
document.getElementById("searchResults").addEventListener("click", function(e){
  const item = e.target.closest("[data-poem-id]");
  if(item){ openPoem(item.getAttribute("data-poem-id")); closeSearchModal(); }
});

// ---------- شريط التنقل: ظل عند التمرير + قائمة الموبايل + تبديل اللغة ----------
const navbar = document.getElementById("navbar");
window.addEventListener("scroll", function(){
  navbar.classList.toggle("is-scrolled", window.scrollY > 10);
}, { passive: true });

const burgerBtn = document.getElementById("burgerBtn");
const mobileMenu = document.getElementById("mobileMenu");
function closeMobileMenu(){
  burgerBtn.classList.remove("is-open");
  mobileMenu.classList.remove("is-open");
}
burgerBtn.addEventListener("click", function(){
  burgerBtn.classList.toggle("is-open");
  mobileMenu.classList.toggle("is-open");
});

document.querySelectorAll(".lang-switch button").forEach(function(btn){
  btn.addEventListener("click", function(){
    const lang = btn.getAttribute("data-lang");
    if(lang === currentLang) return;
    currentLang = lang;
    applyTranslations();
  });
});

/* ======================================================================
   المودالات العامة (فتح/إغلاق)
   ====================================================================== */
function openModal(id){ document.getElementById(id).classList.add("is-open"); }
function closeModal(id){ document.getElementById(id).classList.remove("is-open"); }
function closeAllModals(){
  document.querySelectorAll(".modal-overlay").forEach(function(m){ m.classList.remove("is-open"); });
}
document.querySelectorAll("[data-close-modal]").forEach(function(btn){
  btn.addEventListener("click", function(){ closeModal(btn.getAttribute("data-close-modal")); });
});
document.querySelectorAll(".modal-overlay").forEach(function(overlay){
  overlay.addEventListener("click", function(e){ if(e.target === overlay) overlay.classList.remove("is-open"); });
});

function clearFieldErrors(form){
  form.querySelectorAll(".field").forEach(function(f){ f.classList.remove("has-error"); });
}
function setFieldError(fieldEl, hasError, customMessage){
  fieldEl.classList.toggle("has-error", !!hasError);
  if(hasError && customMessage){
    const errEl = fieldEl.querySelector(".field-error");
    if(errEl) errEl.textContent = customMessage;
  }
}

/* ======================================================================
   10) تسجيل الدخول الآمن عبر Firebase Authentication
   ======================================================================
   - لا يوجد أي اسم مستخدم أو كلمة مرور مكتوبة في هذا الملف.
   - عملية الدخول الفعلية تتم بالكامل عبر signInWithEmailAndPassword، التي
     تُرسل البيانات مباشرة إلى خوادم Firebase للتحقق، ولا تُقارَن أي قيمة
     محليًا في هذا الكود.
   - حساب الأدمن يُنشأ من Firebase Console فقط (انظر دليل النشر المرفق).
   ====================================================================== */
const loginForm = document.getElementById("loginForm");
const loginSubmitBtn = loginForm.querySelector("button[type=submit]");

loginForm.addEventListener("submit", async function(e){
  e.preventDefault();
  clearFieldErrors(loginForm);

  const emailField = document.getElementById("fieldEmail");
  const passwordField = document.getElementById("fieldPassword");
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;

  let hasError = false;
  if(!email){ setFieldError(emailField, true, t("login_error_required")); hasError = true; }
  else if(!isValidEmail(email)){ setFieldError(emailField, true, t("login_error_email")); hasError = true; }
  if(!password){ setFieldError(passwordField, true, t("login_error_required")); hasError = true; }
  if(hasError) return;

  loginSubmitBtn.disabled = true;
  const originalLabel = loginSubmitBtn.textContent;
  loginSubmitBtn.textContent = t("login_submitting");

  try{
    await loginWithEmail(email, password);
    showToast(t("login_success_toast"));
    goToPage("admin");
  }catch(err){
    setFieldError(passwordField, true, firebaseAuthErrorMessage(err.code));
  }finally{
    loginSubmitBtn.disabled = false;
    loginSubmitBtn.textContent = originalLabel;
  }
});

// تسجيل خروج آمن: ينهي جلسة Firebase فعليًا، ثم يعيد توجيه الزائر للصفحة الرئيسية.
// بعد تنفيذ signOut، onAuthStateChanged أعلاه سيُحدّث currentUser إلى null تلقائيًا
// ويحمي أي محاولة وصول لاحقة لصفحة admin دون الحاجة لأي منطق إضافي هنا.
document.getElementById("adminLogoutBtn").addEventListener("click", async function(){
  const btn = this;
  btn.disabled = true;
  try{
    await logoutUser();
    showToast(t("toast_logged_out"));
    goToPage("home");
  }catch(err){
    console.error("Logout error:", err.code || err.message);
    showToast(t("toast_firestore_error"), "danger");
  }finally{
    btn.disabled = false;
  }
});

/* ======================================================================
   11) لوحة التحكم: التنقل بين البانلات + بدء الاشتراكات اللحظية
   ====================================================================== */
document.querySelectorAll(".admin-nav-btn[data-admin-panel]").forEach(function(btn){
  btn.addEventListener("click", function(){
    document.querySelectorAll(".admin-nav-btn[data-admin-panel]").forEach(function(b){ b.classList.remove("active"); });
    document.querySelectorAll(".admin-panel").forEach(function(p){ p.classList.remove("is-active"); });
    btn.classList.add("active");
    document.getElementById("panel-" + btn.getAttribute("data-admin-panel")).classList.add("is-active");
  });
});

let adminSubscriptionsStarted = false;

// تبدأ الاشتراكات اللحظية بإدارة القصائد/التصنيفات/الاقتباسات فقط بعد دخول الأدمن فعليًا للوحة
// (لا قبل ذلك، حتى لو كانت قواعد الأمان تسمح بالقراءة العامة لبعض الحقول لاحقًا)
function startAdminSubscriptions(){
  if(adminSubscriptionsStarted) return;
  adminSubscriptionsStarted = true;

  if(unsubAdminPoems) unsubAdminPoems();
  unsubAdminPoems = subscribeToAllPoemsAdmin(function(poems){
    ADMIN_POEMS_CACHE = poems;
    renderAdminStats();
    renderAdminPoemsTable();
  });

  refreshPoemFormCategoryOptions();
  renderAdminCategoriesTable();
  renderAdminQuotesTable();
}

/* ====================================================================
   لوحة الإحصائيات
   ==================================================================== */
function renderAdminStats(){
  const totalReads = ADMIN_POEMS_CACHE.reduce(function(sum,p){ return sum + (p.reads||0); }, 0);
  document.getElementById("statTotalPoems").textContent = ADMIN_POEMS_CACHE.length;
  document.getElementById("statTotalReads").textContent = formatNumber(totalReads);
  document.getElementById("statTotalCategories").textContent = CATEGORIES_CACHE.length;
  document.getElementById("statTotalQuotes").textContent = QUOTES_CACHE.length;

  const mostRead = ADMIN_POEMS_CACHE.slice().sort(function(a,b){ return b.reads - a.reads; }).slice(0,5);
  document.getElementById("statsMostReadList").innerHTML = mostRead.map(function(p){
    return '<div class="mini-row"><span class="mr-title">' + escapeHTML(getPoemTitle(p)) + '</span><span class="mr-value">' + formatNumber(p.reads) + '</span></div>';
  }).join("") || ('<p style="color:var(--muted);font-size:0.85rem;">' + t("empty_no_poems") + '</p>');

  const latest = ADMIN_POEMS_CACHE.slice().sort(function(a,b){ return new Date(b.date) - new Date(a.date); }).slice(0,5);
  document.getElementById("statsLatestList").innerHTML = latest.map(function(p){
    return '<div class="mini-row"><span class="mr-title">' + escapeHTML(getPoemTitle(p)) + ' ' +
      (p.status === "draft" ? '<span class="badge" style="margin-inline-start:6px;">' + t("status_draft") + '</span>' : '') +
      '</span><span class="mr-value">' + formatDate(p.date) + '</span></div>';
  }).join("") || ('<p style="color:var(--muted);font-size:0.85rem;">' + t("empty_no_poems") + '</p>');
}

/* ====================================================================
   إدارة القصائد (CRUD متصل بـ Firestore + رفع صور الغلاف)
   ==================================================================== */
let adminPoemsSearchTerm = "";

function renderAdminPoemsTable(){
  let list = ADMIN_POEMS_CACHE.slice().sort(function(a,b){ return new Date(b.date) - new Date(a.date); });
  if(adminPoemsSearchTerm){
    const term = adminPoemsSearchTerm.toLowerCase();
    list = list.filter(function(p){ return getPoemTitle(p).toLowerCase().indexOf(term) !== -1; });
  }
  const tbody = document.getElementById("adminPoemsTableBody");
  const emptyEl = document.getElementById("adminPoemsEmpty");

  if(list.length === 0){
    tbody.innerHTML = ""; emptyEl.style.display = "block";
    return;
  }
  emptyEl.style.display = "none";

  tbody.innerHTML = list.map(function(p){
    const cat = getCategoryById(p.category);
    const statusBadge = p.status === "published"
      ? '<span class="badge" style="color:var(--success);border-color:var(--success);">' + t("status_published") + '</span>'
      : '<span class="badge">' + t("status_draft") + '</span>';
    return (
      '<tr>' +
        '<td data-label="' + t("th_title") + '"><span class="row-title">' + escapeHTML(getPoemTitle(p)) + '</span></td>' +
        '<td data-label="' + t("th_category") + '"><span class="badge">' + (cat ? escapeHTML(getCategoryName(cat)) : "—") + '</span></td>' +
        '<td data-label="' + t("th_date") + '">' + formatDate(p.date) + '</td>' +
        '<td data-label="' + t("th_reads") + '">' + formatNumber(p.reads) + '</td>' +
        '<td data-label="' + t("th_status") + '">' + statusBadge + '</td>' +
        '<td data-label="' + t("th_actions") + '">' +
          '<div class="row-actions">' +
            (p.status === "published" ?
            '<button class="btn-icon" data-action="view-poem" data-id="' + p.id + '" aria-label="' + t("view_action") + '" title="' + t("view_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>' +
            '</button>' : '') +
            '<button class="btn-icon" data-action="edit-poem" data-id="' + p.id + '" aria-label="' + t("edit_action") + '" title="' + t("edit_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>' +
            '</button>' +
            '<button class="btn-icon" data-action="delete-poem" data-id="' + p.id + '" aria-label="' + t("delete_action") + '" title="' + t("delete_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>' +
            '</button>' +
          '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join("");
}

document.getElementById("adminPoemsSearch").addEventListener("input", function(){
  adminPoemsSearchTerm = this.value;
  renderAdminPoemsTable();
});

function refreshPoemFormCategoryOptions(){
  const select = document.getElementById("poemFormCategory");
  select.innerHTML = CATEGORIES_CACHE.map(function(c){ return '<option value="' + c.id + '">' + escapeHTML(getCategoryName(c)) + '</option>'; }).join("");
}

// حالة رفع الصورة الحالية في النموذج (تُحفظ مؤقتًا هنا حتى الضغط على حفظ/نشر)
let pendingCoverFile = null;
let pendingCoverPreviewUrl = "";
let editingPoemExistingCoverUrl = "";

document.getElementById("addPoemBtn").addEventListener("click", function(){
  document.getElementById("poemModalTitle").textContent = t("modal_add_poem_title");
  document.getElementById("poemForm").reset();
  document.getElementById("poemFormId").value = "";
  pendingCoverFile = null; pendingCoverPreviewUrl = ""; editingPoemExistingCoverUrl = "";
  updateCoverPreview("");
  refreshPoemFormCategoryOptions();
  document.getElementById("poemFormDate").value = new Date().toISOString().slice(0,10);
  document.getElementById("poemFormStatus").value = "draft";
  clearFieldErrors(document.getElementById("poemForm"));
  openModal("poemModal");
});

document.getElementById("adminPoemsTableBody").addEventListener("click", function(e){
  const btn = e.target.closest("[data-action]");
  if(!btn) return;
  const action = btn.getAttribute("data-action");
  const id = btn.getAttribute("data-id");

  if(action === "view-poem"){
    goToPage("poem", { poemId: id });
  }
  if(action === "edit-poem"){
    const poem = ADMIN_POEMS_CACHE.find(function(p){ return p.id === id; });
    if(!poem) return;
    document.getElementById("poemModalTitle").textContent = t("modal_edit_poem_title");
    refreshPoemFormCategoryOptions();
    document.getElementById("poemFormId").value = poem.id;
    document.getElementById("poemFormTitle").value = poem.title_ar;
    document.getElementById("poemFormCategory").value = poem.category;
    document.getElementById("poemFormDate").value = poem.date;
    document.getElementById("poemFormBody").value = poem.body_ar;
    document.getElementById("poemFormStatus").value = poem.status || "draft";
    pendingCoverFile = null; pendingCoverPreviewUrl = "";
    editingPoemExistingCoverUrl = poem.coverImageUrl || "";
    updateCoverPreview(editingPoemExistingCoverUrl);
    clearFieldErrors(document.getElementById("poemForm"));
    openModal("poemModal");
  }
  if(action === "delete-poem"){
    pendingDeleteAction = async function(){
      try{
        await deletePoemById(id);
        showToast(t("toast_poem_deleted"));
      }catch(err){
        console.error("deletePoem error:", err.code || err.message);
        showToast(t("toast_firestore_error"), "danger");
      }
    };
    openModal("confirmModal");
  }
});

// معاينة صورة الغلاف فور اختيارها + تحقق من النوع والحجم قبل أي رفع فعلي
function updateCoverPreview(url){
  const previewEl = document.getElementById("poemCoverPreview");
  if(!previewEl) return;
  if(url){
    previewEl.style.backgroundImage = "url('" + url + "')";
    previewEl.classList.add("has-image");
  }else{
    previewEl.style.backgroundImage = "";
    previewEl.classList.remove("has-image");
  }
}

document.getElementById("poemFormCoverInput").addEventListener("change", function(){
  const file = this.files && this.files[0];
  if(!file) return;
  const validation = validateImageFile(file);
  if(!validation.ok){
    showToast(validation.reason === "too_large" ? t("toast_image_too_large") : t("toast_image_invalid_type"), "danger");
    this.value = "";
    return;
  }
  pendingCoverFile = file;
  pendingCoverPreviewUrl = URL.createObjectURL(file);
  updateCoverPreview(pendingCoverPreviewUrl);
});

async function handlePoemFormSubmit(targetStatus){
  const form = document.getElementById("poemForm");
  clearFieldErrors(form);

  const titleField = document.getElementById("poemFormTitle");
  const bodyField = document.getElementById("poemFormBody");
  const title = sanitizeText(titleField.value, 200);
  const body = sanitizeText(bodyField.value, 20000);
  const category = document.getElementById("poemFormCategory").value;
  const date = document.getElementById("poemFormDate").value || new Date().toISOString().slice(0,10);
  const existingId = document.getElementById("poemFormId").value;

  let hasError = false;
  if(!title){ setFieldError(titleField.closest(".field"), true); hasError = true; }
  if(!body){ setFieldError(bodyField.closest(".field"), true); hasError = true; }
  if(!category){ showToast(t("toast_firestore_error"), "danger"); hasError = true; }
  if(hasError) return;

  const saveBtn = document.getElementById("poemFormSaveBtn") || form.querySelector("button[type=submit]");
  const draftBtn = document.getElementById("poemFormDraftBtn");
  if(saveBtn) saveBtn.disabled = true;
  if(draftBtn) draftBtn.disabled = true;

  try{
    let coverImageUrl = editingPoemExistingCoverUrl || "";
    const poemIdForUpload = existingId || makeTempIdForUpload();

    if(pendingCoverFile){
      if(saveBtn) saveBtn.textContent = t("btn_uploading");
      coverImageUrl = await uploadCoverImage(poemIdForUpload, pendingCoverFile);
    }

    const payload = {
      title_ar: title, title_en: "", category: category, date: date,
      body_ar: body, body_en: "", coverImageUrl: coverImageUrl, status: targetStatus
    };

    if(existingId){
      await updatePoem(existingId, payload);
      showToast(t("toast_poem_updated"));
    }else{
      await createPoem(payload);
      showToast(t("toast_poem_added"));
    }
    closeModal("poemModal");
  }catch(err){
    console.error("savePoem error:", err.code || err.message);
    showToast(t("toast_firestore_error"), "danger");
  }finally{
    if(saveBtn){ saveBtn.disabled = false; saveBtn.textContent = t("btn_publish"); }
    if(draftBtn) draftBtn.disabled = false;
    pendingCoverFile = null;
  }
}

// معرّف مؤقت لمسار رفع الصورة عند إنشاء قصيدة جديدة (قبل أن يكون لها معرّف Firestore حقيقي)
function makeTempIdForUpload(){
  return "tmp-" + Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

document.getElementById("poemFormDraftBtn").addEventListener("click", function(e){
  e.preventDefault();
  handlePoemFormSubmit("draft");
});
document.getElementById("poemForm").addEventListener("submit", function(e){
  e.preventDefault();
  handlePoemFormSubmit("published");
});

/* ====================================================================
   إدارة التصنيفات (CRUD متصل بـ Firestore)
   ==================================================================== */
function renderAdminCategoriesTable(){
  const tbody = document.getElementById("adminCategoriesTableBody");
  tbody.innerHTML = CATEGORIES_CACHE.map(function(c){
    const count = ADMIN_POEMS_CACHE.filter(function(p){ return p.category === c.id; }).length;
    return (
      '<tr>' +
        '<td data-label="' + t("th_category_name") + '"><span class="row-title">' + escapeHTML(getCategoryName(c)) + '</span></td>' +
        '<td data-label="' + t("th_poems_count") + '">' + count + '</td>' +
        '<td data-label="' + t("th_actions") + '">' +
          '<div class="row-actions">' +
            '<button class="btn-icon" data-action="edit-cat" data-id="' + c.id + '" aria-label="' + t("edit_action") + '" title="' + t("edit_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>' +
            '</button>' +
            '<button class="btn-icon" data-action="delete-cat" data-id="' + c.id + '" aria-label="' + t("delete_action") + '" title="' + t("delete_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>' +
            '</button>' +
          '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join("");
}

document.getElementById("addCategoryBtn").addEventListener("click", function(){
  document.getElementById("categoryModalTitle").textContent = t("modal_add_category_title");
  document.getElementById("categoryForm").reset();
  document.getElementById("categoryFormId").value = "";
  clearFieldErrors(document.getElementById("categoryForm"));
  openModal("categoryModal");
});

document.getElementById("adminCategoriesTableBody").addEventListener("click", function(e){
  const btn = e.target.closest("[data-action]");
  if(!btn) return;
  const action = btn.getAttribute("data-action");
  const id = btn.getAttribute("data-id");

  if(action === "edit-cat"){
    const cat = getCategoryById(id);
    if(!cat) return;
    document.getElementById("categoryModalTitle").textContent = t("modal_edit_category_title");
    document.getElementById("categoryFormId").value = cat.id;
    document.getElementById("categoryFormName").value = cat.name_ar;
    clearFieldErrors(document.getElementById("categoryForm"));
    openModal("categoryModal");
  }
  if(action === "delete-cat"){
    const inUse = ADMIN_POEMS_CACHE.some(function(p){ return p.category === id; });
    if(inUse){
      showToast(t("toast_category_in_use"), "danger");
      return;
    }
    pendingDeleteAction = async function(){
      try{
        await deleteCategoryById(id);
        showToast(t("toast_category_deleted"));
      }catch(err){
        console.error("deleteCategory error:", err.code || err.message);
        showToast(t("toast_firestore_error"), "danger");
      }
    };
    openModal("confirmModal");
  }
});

document.getElementById("categoryForm").addEventListener("submit", async function(e){
  e.preventDefault();
  clearFieldErrors(e.target);
  const nameField = document.getElementById("categoryFormName");
  const name = sanitizeText(nameField.value, 60);
  const existingId = document.getElementById("categoryFormId").value;

  if(!name){ setFieldError(nameField.closest(".field"), true); return; }

  try{
    if(existingId){
      await updateCategoryById(existingId, name, "");
      showToast(t("toast_category_updated"));
    }else{
      await createCategory(name, "");
      showToast(t("toast_category_added"));
    }
    closeModal("categoryModal");
  }catch(err){
    console.error("saveCategory error:", err.code || err.message);
    showToast(t("toast_firestore_error"), "danger");
  }
});

/* ====================================================================
   إدارة الاقتباسات (CRUD متصل بـ Firestore)
   ==================================================================== */
function renderAdminQuotesTable(){
  const tbody = document.getElementById("adminQuotesTableBody");
  tbody.innerHTML = QUOTES_CACHE.map(function(q){
    const shortText = getQuoteText(q).length > 60 ? getQuoteText(q).slice(0,60) + "…" : getQuoteText(q);
    return (
      '<tr>' +
        '<td data-label="' + t("th_quote_text") + '"><span class="row-title" style="font-size:0.95rem;">' + escapeHTML(shortText) + '</span></td>' +
        '<td data-label="' + t("th_source") + '">' + escapeHTML(q.source || "—") + '</td>' +
        '<td data-label="' + t("th_actions") + '">' +
          '<div class="row-actions">' +
            '<button class="btn-icon" data-action="edit-quote" data-id="' + q.id + '" aria-label="' + t("edit_action") + '" title="' + t("edit_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>' +
            '</button>' +
            '<button class="btn-icon" data-action="delete-quote" data-id="' + q.id + '" aria-label="' + t("delete_action") + '" title="' + t("delete_action") + '">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>' +
            '</button>' +
          '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join("");
}

document.getElementById("addQuoteBtn").addEventListener("click", function(){
  document.getElementById("quoteModalTitle").textContent = t("modal_add_quote_title");
  document.getElementById("quoteForm").reset();
  document.getElementById("quoteFormId").value = "";
  clearFieldErrors(document.getElementById("quoteForm"));
  openModal("quoteModal");
});

document.getElementById("adminQuotesTableBody").addEventListener("click", function(e){
  const btn = e.target.closest("[data-action]");
  if(!btn) return;
  const action = btn.getAttribute("data-action");
  const id = btn.getAttribute("data-id");

  if(action === "edit-quote"){
    const quote = QUOTES_CACHE.find(function(q){ return q.id === id; });
    if(!quote) return;
    document.getElementById("quoteModalTitle").textContent = t("modal_edit_quote_title");
    document.getElementById("quoteFormId").value = quote.id;
    document.getElementById("quoteFormText").value = quote.text_ar;
    document.getElementById("quoteFormSource").value = quote.source || "";
    clearFieldErrors(document.getElementById("quoteForm"));
    openModal("quoteModal");
  }
  if(action === "delete-quote"){
    pendingDeleteAction = async function(){
      try{
        await deleteQuoteById(id);
        showToast(t("toast_quote_deleted"));
      }catch(err){
        console.error("deleteQuote error:", err.code || err.message);
        showToast(t("toast_firestore_error"), "danger");
      }
    };
    openModal("confirmModal");
  }
});

document.getElementById("quoteForm").addEventListener("submit", async function(e){
  e.preventDefault();
  clearFieldErrors(e.target);
  const textField = document.getElementById("quoteFormText");
  const text = sanitizeText(textField.value, 400);
  const source = sanitizeText(document.getElementById("quoteFormSource").value, 120);
  const existingId = document.getElementById("quoteFormId").value;

  if(!text){ setFieldError(textField.closest(".field"), true); return; }

  try{
    if(existingId){
      await updateQuoteById(existingId, text, "", source);
      showToast(t("toast_quote_updated"));
    }else{
      await createQuote(text, "", source);
      showToast(t("toast_quote_added"));
    }
    closeModal("quoteModal");
  }catch(err){
    console.error("saveQuote error:", err.code || err.message);
    showToast(t("toast_firestore_error"), "danger");
  }
});

/* ====================================================================
   مودال تأكيد الحذف العام (يُستخدم من القصائد/التصنيفات/الاقتباسات)
   ==================================================================== */
document.getElementById("confirmDeleteBtn").addEventListener("click", async function(){
  if(typeof pendingDeleteAction === "function"){
    const btn = this;
    btn.disabled = true;
    await pendingDeleteAction();
    btn.disabled = false;
    pendingDeleteAction = null;
  }
  closeModal("confirmModal");
});

/* ====================================================================
   النشرة البريدية (تذييل الموقع)
   ==================================================================== */
document.getElementById("newsletterBtn").addEventListener("click", function(){
  const input = this.parentElement.querySelector("input[type=email]");
  const value = input.value.trim();
  if(!value || !isValidEmail(value)){
    input.style.borderColor = "var(--danger)";
    setTimeout(function(){ input.style.borderColor = ""; }, 1500);
    return;
  }
  showToast(t("toast_newsletter"));
  input.value = "";
});

/* ======================================================================
   12) التشغيل الأولي للموقع (Bootstrap)
   ======================================================================
   يبدأ فقط بعد أن تتضح حالة Firebase Auth لأول مرة (انظر onAuthStateChanged
   أعلاه)، لتجنب أي ومضة غير صحيحة في الواجهة (مثل ظهور لوحة التحكم للحظة
   قبل اكتشاف أن المستخدم غير مسجل).
   ====================================================================== */
function bootstrapApp(){
  applyTranslations();
  startHeroTaglineAnimation();

  // الاشتراكات اللحظية العامة (متاحة لكل الزوار بدون تسجيل دخول، تحكمها Firestore Rules للقراءة فقط)
  unsubPoems = subscribeToPublishedPoems(function(){
    firstPoemsSnapshotArrived = true;
    renderHomeContent();
    renderArchivePage(currentArchiveFilter, currentSearchTerm);
    if(currentPoemId){ renderPoemPage(currentPoemId); }
  });
  unsubCategories = subscribeToCategories(function(){
    renderHomeContent();
    renderCategoriesPage();
    renderArchivePage(currentArchiveFilter, currentSearchTerm);
  });
  unsubQuotes = subscribeToQuotes(function(){
    renderHomeContent();
    renderQuotesPage();
  });

  // إن وُجد معطى poem= في رابط الصفحة، نحاول فتح القصيدة المطلوبة بعد وصول أول دفعة بيانات
  const params = new URLSearchParams(window.location.search);
  const poemParam = params.get("poem");

  if(poemParam){
    // ننتظر أول استجابة فعلية من القصائد المنشورة قبل تحديد ما إذا كانت القصيدة موجودة
    const waitForPoem = setInterval(function(){
      if(firstPoemsSnapshotArrived){
        clearInterval(waitForPoem);
        if(getPoemById(poemParam)){
          goToPage("poem", { poemId: poemParam });
        }else{
          goToPage("home");
        }
      }
    }, 80);
  }else{
    goToPage("home");
  }
}

/* ==========================
   Background Music
========================== */

const bgMusic = document.getElementById("bgMusic");
const menuMusic = document.getElementById("menuMusic");

if (bgMusic && menuMusic) {

    // مستوى الصوت
    bgMusic.volume = 0.3;

    let started = false;

    // حالة الموسيقى المحفوظة
    let musicEnabled = localStorage.getItem("musicEnabled");

    if (musicEnabled === null) {
        musicEnabled = "true";
        localStorage.setItem("musicEnabled", "true");
    }

    function updateMusicButton() {

        if (bgMusic.paused) {
            menuMusic.innerHTML = "🎵 <span>تشغيل الموسيقى</span>";
        } else {
            menuMusic.innerHTML = "🎵 <span>إيقاف الموسيقى</span>";
        }

    }

    function startMusic() {

        if (started) return;

        started = true;

        if (musicEnabled === "true") {

            bgMusic.play().then(() => {
                updateMusicButton();
            }).catch(() => {});

        } else {

            updateMusicButton();

        }

    }

    // أول تفاعل
    document.addEventListener("pointerdown", startMusic, { once: true });
    document.addEventListener("keydown", startMusic, { once: true });

    // زر الموسيقى داخل القائمة
    menuMusic.addEventListener("click", function (e) {

        e.preventDefault();

        if (bgMusic.paused) {

            bgMusic.play().catch(() => {});

            musicEnabled = "true";
            localStorage.setItem("musicEnabled", "true");

        } else {

            bgMusic.pause();

            musicEnabled = "false";
            localStorage.setItem("musicEnabled", "false");

        }

        updateMusicButton();

    });

    updateMusicButton();

}


/* ==========================
   Light / Dark Mode
========================== */

const toggleTheme = document.getElementById("toggleTheme");

if (toggleTheme) {

    // تحميل آخر وضع محفوظ
    const savedTheme = localStorage.getItem("theme");

    if (savedTheme === "light") {
        document.body.classList.add("light-mode");
        toggleTheme.innerHTML = "🌑 <span>الوضع الداكن</span>";
    }

    toggleTheme.addEventListener("click", function (e) {

        e.preventDefault();

        document.body.classList.toggle("light-mode");

        if (document.body.classList.contains("light-mode")) {

            localStorage.setItem("theme", "light");
            toggleTheme.innerHTML = "🌑 <span>الوضع الداكن</span>";

        } else {

            localStorage.setItem("theme", "dark");
            toggleTheme.innerHTML = "🌙 <span>الوضع الفاتح</span>";

        }

    });

}

/* ==========================
   Support DLM
========================== */

const supportDLM = document.getElementById("supportDLM");

if (supportDLM) {

    supportDLM.addEventListener("click", function (e) {

        e.preventDefault();

        alert("🤍 دعم دلم سيكون متاحًا قريبًا.\n\nنعمل حاليًا على اختيار أفضل وسيلة دعم تناسب جميع الدول.");

    });

}

/* ==========================
   Share Website
========================== */

const shareSite = document.getElementById("shareSite");

if (shareSite) {

    shareSite.addEventListener("click", async function (e) {

        e.preventDefault();

        const shareData = {
            title: "دلم",
            text: "اكتشف أجمل القصائد والاقتباسات في موقع دلم 🤍",
            url: window.location.href
        };

        if (navigator.share) {

            try {
                await navigator.share(shareData);
            } catch (err) {}

        } else {

            try {

                await navigator.clipboard.writeText(window.location.href);

                alert("📋 تم نسخ رابط الموقع.");

            } catch (err) {

                prompt("انسخ رابط الموقع:", window.location.href);

            }

        }

    });

}

/* ==========================
   Welcome Popup
========================== */

const welcomeOverlay = document.getElementById("welcomeOverlay");
const startJourney = document.getElementById("startJourney");

if (welcomeOverlay && startJourney) {

    // تظهر مرة كل 30 يوم
    const lastVisit = localStorage.getItem("dlm_welcome");

    const now = Date.now();

    const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

    if (!lastVisit || (now - Number(lastVisit)) > THIRTY_DAYS) {

        setTimeout(() => {

            welcomeOverlay.classList.add("show");

        }, 800);

    }

    startJourney.addEventListener("click", () => {

        welcomeOverlay.classList.remove("show");

        localStorage.setItem("dlm_welcome", now);

    });

    // إغلاق عند الضغط خارج النافذة
    welcomeOverlay.addEventListener("click", (e) => {

        if (e.target === welcomeOverlay) {

            welcomeOverlay.classList.remove("show");

            localStorage.setItem("dlm_welcome", now);

        }

    });

}





