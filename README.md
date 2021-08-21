# driver-filter
Драйвер-фильтр, осуществляющий перехват операций доступа согласно дискреционной политике доступа.

Для взаимодействия с разработанным драйвером используется приложение уровня пользователя, осуществляющее задание через консоль прав доступа, их сохранение в конфигурационный файл и инициирование обновления правил драйвером через механизм IOCTL-запросов. Конфигурационный файл представляет из себя файл в формате .sql.

Также в разработанном драйвере присутсвует механизм нотификаторов (событие создания/завершения процесса).

## Команды пользовательского приложения
1)	**show** – показать все права;
2)	**new_r** – добавить новое право, в случае, если пара «имя файла-пользователь» уже существуют просто меняется маска доступа;
3)	**del_r** – удалить право;
4)	**update_r** – отправка команды драйверу для обновления информации;
5)	**enable_n** - отправка команды драйверу для установки нотификатора;
6)	**disable_n** – отправка команды драйверу для снятия нотификатора;
7)	**exit** – выход из пользовательского приложения.


