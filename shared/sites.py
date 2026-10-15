"""Ready-made sites for the HTTP emulator: complete, editable sets of pages and routes.

Both are ordinary profile configurations and can be changed block by block in the page
constructor. The organisations are invented: the name comes from the "identity" setting
(the {title} placeholder), there are no addresses or telephone numbers, and no page asks a
visitor for payment or personal details. The only form is the sign-in form, whose password
the emulator discards.
"""


SHOP_MENU = {"type": "links", "items": [
    {"label": "Каталог", "href": "/catalog"}, {"label": "Скидки", "href": "/sale"}, {"label": "Доставка", "href": "/delivery"},
    {"label": "Контакты", "href": "/contacts"}, {"label": "Корзина", "href": "/cart"}, {"label": "Войти", "href": "/login"}]}


def product(name, price, kind, color, href="/catalog", note=""):
    return {"name": name, "price": price, "kind": kind, "color": color, "href": href, "note": note}


HOODIE, TEE, JEANS = "/product/hoodie-basic", "/product/tee-classic", "/product/jeans-straight"
NEW_ITEMS = [
    product("Худи Basic", "4 990 ₽", "hoodie", "grey", HOODIE, "Новинка"),
    product("Футболка Classic", "1 490 ₽", "tshirt", "white", TEE),
    product("Джинсы Straight", "5 490 ₽", "jeans", "navy", JEANS),
    product("Куртка Field", "9 990 ₽", "jacket", "olive", note="Новинка"),
    product("Кеды Court", "6 290 ₽", "sneakers", "white"),
    product("Платье Linen", "5 990 ₽", "dress", "beige"),
]
ALL_ITEMS = NEW_ITEMS + [
    product("Худи Basic", "4 990 ₽", "hoodie", "black", HOODIE),
    product("Футболка Classic", "1 490 ₽", "tshirt", "black", TEE),
    product("Футболка Classic", "1 490 ₽", "tshirt", "green", TEE),
    product("Кепка Daily", "1 290 ₽", "cap", "navy"),
    product("Сумка Tote", "2 490 ₽", "bag", "brown"),
    product("Джинсы Straight", "5 490 ₽", "jeans", "black", JEANS),
]
SALE_ITEMS = [
    product("Куртка Field", "6 990 ₽", "jacket", "brown", note="−30 %"),
    product("Платье Linen", "3 590 ₽", "dress", "pink", note="−40 %"),
    product("Кеды Court", "4 390 ₽", "sneakers", "red", note="−30 %"),
    product("Футболка Classic", "990 ₽", "tshirt", "blue", TEE, "−35 %"),
]


def product_page(name, price, text, composition, sizes):
    return {"title": f"{name} — {{title}}", "components": [
        SHOP_MENU,
        {"type": "links", "items": [{"label": "← Каталог", "href": "/catalog"}]},
        {"type": "heading", "text": name, "level": 1},
        {"type": "paragraph", "text": text},
        {"type": "status_panel", "title": price, "items": [
            {"label": "Состав", "value": composition, "state": "ok"},
            {"label": "Размеры в наличии", "value": sizes, "state": "ok"},
            {"label": "Доставка", "value": "2–5 дней", "state": "ok"}]},
        {"type": "links", "items": [{"label": "Добавить в корзину", "href": "/cart"}, {"label": "Условия возврата", "href": "/delivery"}]}]}


STORE_SITE = {
    "identity": "Тэйва", "site_description": "Одежда на каждый день", "site_layout": "store",
    "site_footer": "Интернет-магазин одежды и аксессуаров. Доставка по всей стране, возврат в течение 14 дней.",
    "decoy_accounts": ["admin", "manager"], "authentication_mode": "configured-accounts", "login_path": "/login",
    "pages": {
        "home": {"title": "{title} — {description}", "components": [
            SHOP_MENU,
            {"type": "hero", "title": "Осенняя коллекция", "text": "Тёплые худи, плотный хлопок и куртки на каждый день. "
             "Бесплатная доставка при заказе от 5 000 ₽.", "button_label": "Смотреть каталог", "button_href": "/catalog"},
            {"type": "products", "title": "Новинки", "items": NEW_ITEMS},
            {"type": "cards", "title": "Покупать у нас удобно", "items": [
                {"title": "Доставка 2–5 дней", "text": "Курьером до двери или в пункт выдачи рядом с домом."},
                {"title": "Примерка перед оплатой", "text": "Оплачивайте только то, что подошло."},
                {"title": "Возврат 14 дней", "text": "Вернём деньги, если вещь не подошла по размеру или цвету."}]}]},
        "catalog": {"title": "Каталог — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Каталог", "level": 1}, {"type": "products", "items": ALL_ITEMS}]},
        "sale": {"title": "Скидки — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Скидки сезона", "level": 1},
            {"type": "paragraph", "text": "Цены снижены до конца месяца. Количество ограничено."},
            {"type": "products", "items": SALE_ITEMS}]},
        "hoodie": product_page("Худи Basic", "4 990 ₽", "Свободное худи из плотного футера с начёсом. Капюшон на шнурке, "
                               "карман-кенгуру, манжеты на резинке.", "80 % хлопок, 20 % полиэстер", "S, M, L, XL"),
        "tee": product_page("Футболка Classic", "1 490 ₽", "Базовая футболка прямого кроя из плотного хлопка. "
                            "Не теряет форму после стирки.", "100 % хлопок", "XS, S, M, L, XL"),
        "jeans": product_page("Джинсы Straight", "5 490 ₽", "Прямые джинсы со средней посадкой. Плотный деним, "
                              "пять карманов, застёжка на пуговицах.", "98 % хлопок, 2 % эластан", "28–36"),
        "cart": {"title": "Корзина — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Корзина", "level": 1},
            {"type": "paragraph", "text": "В корзине пока пусто. Войдите в личный кабинет, чтобы увидеть сохранённые товары."},
            {"type": "links", "items": [{"label": "Перейти в каталог", "href": "/catalog"}, {"label": "Войти", "href": "/login"}]}]},
        "delivery": {"title": "Доставка и возврат — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Доставка и возврат", "level": 1},
            {"type": "info_panel", "title": "Доставка", "text": "Курьером или в пункт выдачи за 2–5 дней. При заказе от 5 000 ₽ — бесплатно, "
             "иначе 350 ₽."},
            {"type": "info_panel", "title": "Оплата", "text": "При получении, после примерки."},
            {"type": "info_panel", "title": "Возврат", "text": "В течение 14 дней, если сохранены ярлыки и товарный вид. "
             "Заявка на возврат оформляется в личном кабинете."}]},
        "contacts": {"title": "Контакты — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Контакты", "level": 1},
            {"type": "info_panel", "title": "Поддержка", "text": "Ежедневно с 9:00 до 21:00. Напишите нам из личного кабинета — "
             "ответим в течение часа."},
            {"type": "info_panel", "title": "Сотрудничество", "text": "Предложения для поставщиков и оптовых покупателей принимаются "
             "через форму в личном кабинете партнёра."}]},
        "login": {"title": "Вход — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Вход в личный кабинет", "level": 1},
            {"type": "form", "action": "/login", "submit_label": "Войти", "fields": [
                {"name": "username", "label": "Логин или электронная почта", "kind": "text"},
                {"name": "password", "label": "Пароль", "kind": "password"}]},
            {"type": "paragraph", "text": "Забыли пароль? Обратитесь в поддержку."}]},
        "account": {"title": "Личный кабинет — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Личный кабинет", "level": 1},
            {"type": "cards", "items": [
                {"title": "Заказы", "text": "Активных заказов нет."},
                {"title": "Бонусы", "text": "На счёте 0 баллов."},
                {"title": "Обращения", "text": "Открытых обращений нет."}]},
            {"type": "links", "items": [{"label": "В каталог", "href": "/catalog"}]}]},
        "denied": {"title": "Вход — {title}", "components": [
            SHOP_MENU, {"type": "heading", "text": "Не удалось войти", "level": 1},
            {"type": "paragraph", "text": "Неверный логин или пароль. Проверьте данные и попробуйте снова."},
            {"type": "links", "items": [{"label": "Попробовать снова", "href": "/login"}]}]},
    },
    "routes": [
        {"path": "/", "method": "GET", "response": "page", "page": "home"},
        {"path": "/catalog", "method": "GET", "response": "page", "page": "catalog"},
        {"path": "/sale", "method": "GET", "response": "page", "page": "sale"},
        {"path": HOODIE, "method": "GET", "response": "page", "page": "hoodie"},
        {"path": TEE, "method": "GET", "response": "page", "page": "tee"},
        {"path": JEANS, "method": "GET", "response": "page", "page": "jeans"},
        {"path": "/cart", "method": "GET", "response": "page", "page": "cart"},
        {"path": "/delivery", "method": "GET", "response": "page", "page": "delivery"},
        {"path": "/contacts", "method": "GET", "response": "page", "page": "contacts"},
        {"path": "/login", "method": "GET", "response": "page", "page": "login"},
        {"path": "/login", "method": "POST", "response": "login", "page": "account", "failure_page": "denied"},
        {"path": "/account", "method": "GET", "response": "page", "page": "account", "requires_login": True}],
}


PORTAL_MENU = {"type": "links", "items": [
    {"label": "Главная", "href": "/"}, {"label": "Новости", "href": "/news"}, {"label": "Заявки", "href": "/helpdesk"},
    {"label": "Документы", "href": "/documents"}, {"label": "Войти", "href": "/login"}]}
NEWS = [
    {"title": "График работы в праздники", "text": "Опубликован график дежурств подразделений на праздничные дни."},
    {"title": "Обновление почтовой системы", "text": "В субботу с 22:00 до 02:00 почта будет недоступна из-за плановых работ."},
    {"title": "Обучение по охране труда", "text": "Запись на ежегодный курс открыта до конца месяца."},
]

PORTAL_SITE = {
    "identity": "Портал сотрудников", "site_description": "Внутренние сервисы компании", "site_layout": "portal",
    "site_footer": "Только для сотрудников. Действия в системе регистрируются.",
    "decoy_accounts": ["admin", "hr", "it-support"], "authentication_mode": "configured-accounts", "login_path": "/login",
    "pages": {
        "home": {"title": "{title}", "components": [
            PORTAL_MENU,
            {"type": "hero", "title": "{title}", "text": "{description}: заявки в службу поддержки, документы, расчётные листы "
             "и новости компании.", "button_label": "Войти", "button_href": "/login"},
            {"type": "cards", "title": "Новости", "items": NEWS}]},
        "news": {"title": "Новости — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Новости компании", "level": 1}, {"type": "cards", "items": NEWS},
            {"type": "paragraph", "text": "Архив новостей доступен после входа."}]},
        "helpdesk": {"title": "Заявки — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Служба поддержки", "level": 1},
            {"type": "status_panel", "title": "Состояние сервисов", "items": [
                {"label": "Почта", "value": "Работает", "state": "ok"},
                {"label": "Файловое хранилище", "value": "Работает", "state": "ok"},
                {"label": "Удалённый доступ", "value": "Плановые работы", "state": "warning"}]},
            {"type": "paragraph", "text": "Чтобы создать заявку или посмотреть её состояние, войдите в портал."},
            {"type": "links", "items": [{"label": "Войти", "href": "/login"}]}]},
        "login": {"title": "Вход — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Вход для сотрудников", "level": 1},
            {"type": "form", "action": "/login", "submit_label": "Войти", "fields": [
                {"name": "username", "label": "Учётная запись", "kind": "text"},
                {"name": "password", "label": "Пароль", "kind": "password"}]},
            {"type": "paragraph", "text": "Проблемы со входом? Обратитесь в службу поддержки по внутреннему номеру."}]},
        "welcome": {"title": "Рабочий стол — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Рабочий стол", "level": 1},
            {"type": "cards", "items": [
                {"title": "Мои заявки", "text": "Открытых заявок нет."},
                {"title": "Расчётный лист", "text": "Документ за прошлый месяц готов."},
                {"title": "Отпуск", "text": "Остаток: 14 дней."}]},
            {"type": "links", "items": [{"label": "Документы", "href": "/documents"}]}]},
        "documents": {"title": "Документы — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Документы", "level": 1},
            {"type": "status_panel", "title": "Общие документы", "items": [
                {"label": "Правила внутреннего распорядка", "value": "PDF", "state": "ok"},
                {"label": "Положение о командировках", "value": "PDF", "state": "ok"},
                {"label": "Регламент удалённого доступа", "value": "На согласовании", "state": "warning"}]}]},
        "denied": {"title": "Вход — {title}", "components": [
            PORTAL_MENU, {"type": "heading", "text": "Вход не выполнен", "level": 1},
            {"type": "paragraph", "text": "Неверная учётная запись или пароль. После нескольких неудачных попыток учётная запись блокируется."},
            {"type": "links", "items": [{"label": "Попробовать снова", "href": "/login"}]}]},
    },
    "routes": [
        {"path": "/", "method": "GET", "response": "page", "page": "home"},
        {"path": "/news", "method": "GET", "response": "page", "page": "news"},
        {"path": "/helpdesk", "method": "GET", "response": "page", "page": "helpdesk"},
        {"path": "/login", "method": "GET", "response": "page", "page": "login"},
        {"path": "/login", "method": "POST", "response": "login", "page": "welcome", "failure_page": "denied"},
        {"path": "/dashboard", "method": "GET", "response": "page", "page": "welcome", "requires_login": True},
        {"path": "/documents", "method": "GET", "response": "page", "page": "documents", "requires_login": True}],
}
