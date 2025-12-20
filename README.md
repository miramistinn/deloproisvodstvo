# **Программное средство автоматизированного контроля исполнения поручений в системе делопроизводства.**

Проект представляет собой разработку программного средства автоматизированного контроля исполнения поручений в системе делопроизводства. Система предназначена для упрощения управления поручениями, обеспечения прозрачности процессов и своевременного выполнения задач сотрудниками.

Основная цель - автоматизировать процессы контроля исполнения поручений, минимизировать количество просроченных и потерянных задач, повысить эффективность работы сотрудников и улучшить взаимодействие между подразделениями.

К оссновным возможностям относятся: создание и назначение поручений исполнителям, контроль сроков и статусов выполнения, уведомления и напоминания о приближении дедлайнов, формирование отчётности по исполнению поручений, хранение истории изменений и комментариев, управление ролями и доступом пользователей, интеграция с существующими системами документооборота (например, 1С).

Ссылки на репозитории сервера и клиента
Сервер: https://github.com/miramistinn/deloproisvodstvoback
Клиент: https://github.com/miramistinn/deloproisvodstvofront
---

## **Содержание**

1. [Архитектура](#Архитектура)
	1. [C4-модель](#C4-модель)
	2. [Схема данных](#Схема_данных)
2. [Функциональные возможности](#Функциональные_возможности)
	1. [Диаграмма вариантов использования(#Диаграмма_вариантов_использования)]
	2. [User-flow диаграммы](#User-flow_диаграммы)
3. [Детали реализации](#Детали_реализации)
	1. [UML-диаграммы](#UML-диаграммы)
	2. [Спецификация API](#Спецификация_API)
	3. [Безопасность](#Безопасность)
	4. [Оценка качества кода](#Оценка_качества_кода)
4. [Тестирование](#Тестирование)
	1. [Unit-тесты](#Unit-тесты)
	2. [Интеграционные тесты](#Интеграционные_тесты)
5. [Установка и  запуск](#installation)
	1. [Манифесты для сборки docker образов](#Манифесты_для_сборки_docker_образов)
	2. [Манифесты для развертывания k8s кластера](#Манифесты_для_развертывания_k8s_кластера)
6. [Лицензия](#Лицензия)
7. [Контакты](#Контакты)

---
## **Архитектура**

### C4-модель

Первый уровень – это контекстная диаграмма. На этом уровне представляется общая картина системы с ее внешними актерами и их взаимодействием с системой. Представление контекстного уровня представлено на рисунке.

<img width="974" height="598" alt="image" src="https://github.com/user-attachments/assets/8844ec51-36e8-4267-9bb8-d812a4e319c4" />

Второй уровень – контейнерный. Он показывает составные части архитектуры, определенные на уровне 1, декомпозируются для предоставления информации о технических блоках высокого уровня. На рисунке представление контейнерного уровня программного приложения.

<img width="974" height="385" alt="image" src="https://github.com/user-attachments/assets/67b3902a-426a-4260-b09d-16e3950f4c28" />

Третий уровень – компонентный. На этом уровне представляются внутренние блоки контейнеров. Представление компонентного уровня представлено на рисунке. 
 
<img width="913" height="750" alt="image" src="https://github.com/user-attachments/assets/02ad562e-36e9-4c07-ac61-6833ff4c15e4" />

Последний уровень – кодовый. На этом уровне представляется внутренняя организация компонентов, определенных на уровне 3. На рисунке  показано представление кодового уровня.

<img width="974" height="344" alt="image" src="https://github.com/user-attachments/assets/4d0857ab-bd35-47db-8dbb-1e0a4c37b9c6" />

Такое построение приложения основано на паттерне MVC (Model – View – Controller).  Архитектура MVC разделяет приложение на три логических слоя: Model (Модель), View (Представление) и Controller (Контроллер).  


### Схема данных

<img width="974" height="691" alt="image" src="https://github.com/user-attachments/assets/e9b7c761-520d-4777-bf18-e126115c0932" />


---

## **Функциональные возможности**

### Диаграмма вариантов использования

<img width="974" height="680" alt="image" src="https://github.com/user-attachments/assets/c5d86da8-d6b7-4059-91c3-9403c5199e21" />


В системе выделяются два основных действующих лица: Пользователь (Сотрудник) и Администратор, обладающий расширенными правами для контроля и обслуживания системы. Администратор также может являться руководителем. Функциональность сгруппирована вокруг трех главных областей. Первая – управление поручением, позволяет сотруднику выполнять полный цикл работ: от создания или редактирования с указанием всех атрибутов, включая прикрепление документа и назначение исполнителей, до изменения статуса задачи и просмотра общего списка задач. Вторая область, аналитика, представлена вариантом использования просмотр дашборда, где пользователь может фильтровать данные по периоду, статусу и исполнителю для получения статистики. Третья область, профиль и данные, покрывает просмотр профиля и возможность редактирования личных данных (таких как фио, телефон, дата рождения), а также смену пароля. Роль администратора включает в себя все перечисленные функции пользователя, но при этом расширена для выполнения критически важных операций: администратор может управлять служебными данными пользователей, что включает блокировку, смену отдела для любого сотрудника в системе. 


### User-flow диаграммы

<img width="975" height="853" alt="image" src="https://github.com/user-attachments/assets/95434e99-0ce9-4440-84ca-642eadd883e3" />

<img width="849" height="726" alt="image" src="https://github.com/user-attachments/assets/a02d6156-9b78-45a9-ad70-0709c5f80091" />

## **Детали реализации**

### UML-диаграммы

<img width="959" height="928" alt="image" src="https://github.com/user-attachments/assets/e5c8efe0-5e5d-45b7-9053-d4e14da6dc2b" />
<img width="974" height="458" alt="image" src="https://github.com/user-attachments/assets/8ca8725a-8cb9-4754-9856-1c3d049658a2" />
<img width="545" height="499" alt="image" src="https://github.com/user-attachments/assets/23f8c28a-5595-4db2-b6cd-e0c499af191b" />

### Спецификация API

Полная версия по ссылке https://github.com/miramistinn/deloproisvodstvo/blob/main/api.
### Безопасность


	В папке configs расположены классы, обеспечивающие полную настройку системы безопасности приложения. Они отвечают за процесс аутентификации, генерацию и обработку JWT-токенов, управление фильтрами безопасности и правилами доступа к API.
Конфигурация отвечает за кодирование паролей. Используемый алгоритм BCrypt обеспечивает высокий уровень криптостойкости, включённую соль и устойчивость к подбору. Энкодер применяется как при создании новых учётных записей, так и при проверке паролей в процессе входа.

@Configuration
public class EncodeConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
Класс AuthenticationConfig формирует провайдер аутентификации, который использует UserDetailsService для загрузки данных пользователя и PasswordEncoder для проверки корректности пароля. 

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

}}

Фильтр выполняется для каждого запроса и отвечает за обработку JWT-токена. Из заголовка Authorization извлекается токен, после чего из него пытаются получить email пользователя. Если токен успешно прочитан и система безопасности ещё не содержит аутентифицированного пользователя для текущего запроса, сервис загружает данные пользователя по email и проверяет, действителен ли токен. 

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String jwt = authHeader.substring(7);
        String email = null;

        try {
            email = jwtService.extractUsername(jwt);
        } catch (Exception e) {
            log.debug("Failed to extract username from JWT: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.loadUserByUsername(email);
            if (jwtService.isJwtValid(jwt)) {

                if (!userDetails.isEnabled()) {
                    throw new AccessDeniedException(getMessage("error.access.denied"));
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}

Класс securityFilterChain формирует правила доступа ко всем маршрутам приложения, указывает публичные и защищённые эндпоинты и задаёт общую стратегию работы Spring. 

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                            "/api/auth/login",
                            "/api/auth/refresh",
                            "/api/auth/validate",
                            "/api/auth/is-blocked",
                            "/api/auth/service-token",
                            "/api/auth/register"
                    ).permitAll()
                    .requestMatchers(HttpMethod.PATCH, "/api/auth").hasRole("ADMIN")
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    return http.build();
}

Контроллер AuthenticationControllerImpl представляет собой основной точкой входа для всех операций, связанных с аутентификацией, регистрацией и управлением пользователем. Он помечен аннотацией @RestController, что делает его REST-контроллером, обрабатывающим HTTP-запросы. Контроллер использует несколько сервисов: LoginService для аутентификации и получения JWT, JwtService для работы с токенами, а также UserService и UserServiceImpl для управления пользователями.

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

}}

JwtServiceImpl сервис отвечает за создание, проверку и обновление JWT-токенов, используя алгоритм ES512 и приватный/публичный ключи. При генерации access-токена в него помещаются имя пользователя, набор его ролей, тип токена и информация о том, заблокирован ли пользователь.  
Для валидации токена сервис извлекает из него набор claims с помощью публичного ключа и проверяет, не истекло ли время действия. При попытке обновить access-токен сначала проверяется корректность и актуальность входящего токена. 

### Оценка качества кода

 <img width="974" height="204" alt="image" src="https://github.com/user-attachments/assets/a59d5974-330b-485d-a21d-5d3bd825f58d" />
	
Результаты сканирования подтверждают высокую культуру написания кода: полное отсутствие дубликатов и багов на две тысячи строк обеспечило проекту высшие оценки за надежность и удобство сопровождения. Главным препятствием для прохождения проверки стал критический рейтинг безопасности «E», возникший из-за двух открытых уязвимостей и одной потенциально опасной зоны, которые делают систему уязвимой для внешних угроз. 

## **Тестирование**

### Unit-тесты

@ExtendWith(MockitoExtension.class)
class TaskServiceImplTest {

    @Mock
    private TaskRepository taskRepository;

    @Mock
    private CurrentUserRepository currentUserRepository;

    @Mock
    private TaskStatusRepository taskStatusRepository;

    @InjectMocks
    private TaskServiceImpl taskService;

    @Test
    void createTask_success() {
        // given
        TaskDto dto = new TaskDto(
                "Title",
                "Content",
                "TASK-1",
                1L,
                null,
                null,
                LocalDate.now().plusDays(3),
                "NEW",
                List.of(2L, 3L)
        );

        CurrentUser creator = CurrentUser.builder().id(1L).build();
        CurrentUser executor1 = CurrentUser.builder().id(2L).build();
        CurrentUser executor2 = CurrentUser.builder().id(3L).build();
        TaskStatus status = TaskStatus.builder().statusName("New").build();

        when(currentUserRepository.findById(1L)).thenReturn(Optional.of(creator));
        when(currentUserRepository.findAllById(List.of(2L, 3L)))
                .thenReturn(List.of(executor1, executor2));
        when(taskStatusRepository.findByStatusNameIgnoreCase("New"))
                .thenReturn(Optional.of(status));
        when(taskRepository.save(any(Task.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        Task task = taskService.createTask(dto);

        assertThat(task.getTitle()).isEqualTo("Title");
        assertThat(task.getCreator()).isEqualTo(creator);
        assertThat(task.getExecutors()).hasSize(2);
        assertThat(task.getStatus()).isEqualTo(status);

        verify(taskRepository).save(any(Task.class));
    }

    @Test
    void createTask_creatorNotFound_shouldThrow() {

        TaskDto dto = new TaskDto(
                "Title",
                null,
                null,
                99L,
                null,
                null,
                null,
                null,
                null
        );

        when(currentUserRepository.findById(99L))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> taskService.createTask(dto))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void createTask_statusNotFound_shouldThrow() {
        // given
        TaskDto dto = new TaskDto(
                "Title",
                null,
                null,
                1L,
                null,
                null,
                null,
                "New",
                null
        );

        when(currentUserRepository.findById(1L))
                .thenReturn(Optional.of(new CurrentUser()));
        when(taskStatusRepository.findByStatusNameIgnoreCase("UNKNOWN"))
                .thenReturn(Optional.empty());

        // then
        assertThatThrownBy(() -> taskService.createTask(dto))
                .isInstanceOf(TaskStatusNotFoundException.class);
    }

    @Test
    void changeStatus_success() {
        // given
        Task task = Task.builder().id(1L).build();
        TaskStatus status = TaskStatus.builder().statusName("DONE").build();

        when(taskRepository.findById(1L)).thenReturn(Optional.of(task));
        when(taskStatusRepository.findByStatusNameIgnoreCase("DONE"))
                .thenReturn(Optional.of(status));
        when(taskRepository.save(any(Task.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        Task updated = taskService.changeStatus(1L, "Completed");

        assertThat(updated.getStatus()).isEqualTo(status);
    }
}


### Интеграционные тесты

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class TaskControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CurrentUserRepository userRepository;

    @Autowired
    private TaskStatusRepository statusRepository;

    private Long creatorId;

    @BeforeEach
    void setUp() {
        // создаём пользователя
        CurrentUser creator = userRepository.save(
                CurrentUser.builder()
                        .name("Test Creator")
                        .email("creator@test.com")
                        .build()
        );
        creatorId = creator.getId();

        saveStatus("NEW");
        saveStatus("IN PROCCES");
        saveStatus("OVERDUE");
        saveStatus("COMPLETED");
        saveStatus("CANCELLED");
        saveStatus("SUCCESSFULLY COMPLETED");
        saveStatus("REJECTED");
    }

    private void saveStatus(String name) {
        if (statusRepository.findByStatusNameIgnoreCase(name).isEmpty()) {
            statusRepository.save(
                    TaskStatus.builder()
                            .statusName(name)
                            .build()
            );
        }
    }


    @Test
    void createTask_shouldReturn200AndTask() throws Exception {
        mockMvc.perform(post("/api/tasks")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                      "title": "Integration Task",
                      "content": "Test content",
                      "creatorId": %d,
                      "status": "New"
                    }
                    """.formatted(creatorId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.title").value("Integration Task"))
                .andExpect(jsonPath("$.creator.id").value(creatorId))
                .andExpect(jsonPath("$.status.statusName").value("NEW"));
    }


    @Test
    void getTasksByStatus_shouldReturnList() throws Exception {
        mockMvc.perform(get("/api/tasks/by-status")
                        .param("status", "NEW"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }


    @Test
    void changeStatus_shouldUpdateStatus() throws Exception {
        // создаём задачу
        String response = mockMvc.perform(post("/api/tasks")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                      "title": "Task for status change",
                      "creatorId": %d,
                      "status": "New"
                    }
                    """.formatted(creatorId)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        mockMvc.perform(patch("/api/tasks/{id}/status", 1)
                        .param("status", "COMPLETED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status.statusName").value("COMPLETED"));
    }
}

## **Установка и  запуск**

### Манифесты для сборки docker образов

Развертывание происходит с помощью Docker-compose. Сначала необходимо установить Docker. Затем из GitHub выполнить клонирование сервиса и клиентского приложения.
Каждый элемент содержит Dockerfile. Dockerfile для сервиса представлен ниже:
	
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]

	Файл docker-compose.yml для сервера пердставлен ниже:

version: "3.9"

services:
  db:
    image: mysql:8.0
    container_name: deloproizvodstvo-mysql
    environment:
      MYSQL_ROOT_PASSWORD: "1111"
      MYSQL_DATABASE: "deloproisvodstvo"
      MYSQL_USER: "root"
      MYSQL_PASSWORD: "1111"
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - deloproizvodstvo-net

  app:
    build:
      context: ./deloproizvodstvo
      dockerfile: Dockerfile
    container_name: deloproizvodstvo-app
    depends_on:
      - db
    environment:
      SPRING_DATASOURCE_URL: "jdbc:mysql://db:3306/deloproisvodstvo"
      SPRING_DATASOURCE_USERNAME: "root"
      SPRING_DATASOURCE_PASSWORD: "1111"
      SPRING_JPA_HIBERNATE_DDL_AUTO: "update"
      SPRING_JPA_SHOW_SQL: "true"
      SERVER_PORT: "8080"
    ports:
      - "8080:8080"
    networks:
      - deloproizvodstvo-net

volumes:
  db_data:

networks:
  deloproizvodstvo-net:
    driver: bridge

	Для запуска необходимо выполнить команду 

docker compose up –build

Dockerfile для клиентского приложения представлен ниже:
	
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

	Файл docker-compose.yml для сервера пердставлен ниже:

version: '3.8'

services:
  app:
    build: .
    image: frontend:1.0
    ports:
      - "3000:80"
    depends_on:
      - gateway
    environment:
      VITE_API_BASE_URL: http://localhost:8080

  gateway:
    image: gateway:1.0
    ports:
      - "8080:8080"

Файл nginx.conf для клиентского приложения представлен ниже:
	
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://gateway:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}

	Доступ осуществляется по:
	– http://localhost:8080 для cервера;
	– http://localhost:3000 для фронта.

### Манифесты для развертывания k8s кластера

Представить весь код манифестов или ссылки на файлы с ними (при необходимости снабдить комментариями)

---

## **Лицензия**

Этот проект лицензирован по лицензии MIT - подробности представлены в файле [[License.md|LICENSE.md]]

---

## **Контакты**

Автор: olizarovichhhh.4@gamil.com
