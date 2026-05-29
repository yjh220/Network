# 后台管理系统安装指南

## 第一优先级（P0）功能已完成

### 已实现功能

#### 1. 用户管理
- ✅ 用户列表（分页、搜索、筛选）
- ✅ 创建用户
- ✅ 编辑用户信息
- ✅ 删除用户
- ✅ 重置密码
- ✅ 启用/禁用账户
- ✅ 登录日志查询

#### 2. 角色权限管理
- ✅ 角色列表
- ✅ 创建角色
- ✅ 编辑角色
- ✅ 删除角色（非系统角色）
- ✅ 权限分配
- ✅ 预定义权限（30+个权限点）

#### 3. 日志管理
- ✅ 操作日志（增删改查记录）
- ✅ 系统日志（应用运行日志）
- ✅ 登录日志（成功/失败记录）
- ✅ 日志详情查看
- ✅ 旧日志清理

#### 4. 控制台
- ✅ 系统统计数据
- ✅ 流量趋势图
- ✅ 威胁分布图
- ✅ 系统状态监控

### 文件结构

```
Network-Monitoring-master/
├── app2_admin.py                 # 集成后台管理的主应用
├── models_admin.py               # 后台管理数据库模型
├── routes_admin.py               # 后台管理API路由
├── requirements.txt              # 依赖列表
│
├── modules/admin/
│   ├── __init__.py
│   ├── permissions.py            # 权限控制模块
│   ├── log_service.py            # 日志服务模块
│   └── admin_service.py          # 管理服务模块
│
└── templates/admin/
    ├── base.html                 # 后台基础模板
    ├── console.html              # 控制台页面
    ├── users.html                # 用户管理页面
    ├── roles.html                # 角色管理页面
    ├── logs.html                 # 日志管理页面
    ├── monitor.html              # 监控管理（占位）
    ├── threats.html              # 威胁检测（占位）
    ├── alerts.html               # 告警管理（占位）
    ├── defense.html              # 防御管理（占位）
    └── settings.html             # 系统设置（占位）
```

## 安装步骤

### 1. 安装依赖

```bash
cd Network-Monitoring-master
pip install -r requirements.txt
```

### 2. 初始化数据库

```bash
# 初始化权限和角色
flask -c app2_admin.py init-admin

# 创建管理员账户
flask -c app2_admin.py create-admin
```

或者使用Python脚本初始化：

```python
# init_admin_db.py
from app2_admin import app
from models_admin import db
from modules.admin.permissions import PermissionManager
from modules.admin.admin_service import UserService, RoleService

with app.app_context():
    # 创建所有表
    db.create_all()

    # 初始化权限
    PermissionManager.init_permissions()

    # 初始化角色
    PermissionManager.init_roles()

    # 创建管理员
    admin_role = RoleService.get_roles()[0]  # admin角色
    UserService.create_user(
        username='admin',
        email='admin@example.com',
        password='admin123',
        role_id=admin_role.id
    )

    print("初始化完成！")
```

### 3. 启动应用

```bash
python app2_admin.py
```

### 4. 访问系统

- 后台管理: http://127.0.0.1:8080/admin
- 登录用户名: admin
- 登录密码: admin123

## 数据库模型说明

### 核心表

1. **users** - 用户表
2. **roles** - 角色表
3. **permissions** - 权限表
4. **role_permissions** - 角色权限关联表

### 日志表

1. **login_logs** - 登录日志
2. **operation_logs** - 操作日志
3. **system_logs** - 系统日志

### 其他表（已定义，待实现功能）

1. **blocked_ips** - 封禁IP
2. **defense_rules** - 防御规则
3. **alert_rules** - 告警规则
4. **alert_records** - 告警记录
5. **alert_recipients** - 告警接收人
6. **system_configs** - 系统配置
7. **backup_records** - 备份记录

## 权限列表

### 用户管理
- `user.view` - 查看用户
- `user.create` - 创建用户
- `user.edit` - 编辑用户
- `user.delete` - 删除用户
- `user.reset_password` - 重置密码

### 角色管理
- `role.view` - 查看角色
- `role.create` - 创建角色
- `role.edit` - 编辑角色
- `role.delete` - 删除角色
- `role.assign_permission` - 分配权限

### 日志管理
- `log.view` - 查看日志
- `log.export` - 导出日志
- `log.delete` - 删除日志

### 系统管理
- `system.view` - 查看系统
- `system.config` - 系统配置
- `system.backup` - 数据备份

## 使用示例

### 创建新角色

```python
from modules.admin.admin_service import RoleService

# 创建操作员角色（只读权限）
view_permissions = [
    'user.view', 'role.view', 'log.view',
    'monitor.view', 'threat.view', 'alert.view'
]

RoleService.create_role(
    name='operator',
    description='系统操作员',
    permission_ids=view_permissions
)
```

### 检查用户权限

```python
from flask_login import current_user

# 在视图函数中
if current_user.has_permission('user.create'):
    # 允许创建用户
    pass
```

### 使用权限装饰器

```python
from modules.admin.permissions import permission_required

@app.route('/admin/users')
@login_required
@permission_required('user.view')
def user_list():
    return render_template('admin/users.html')
```

## 后续开发计划

### 第二优先级（P1）
- [ ] 监控管理（采集频率、网卡选择、IP黑白名单）
- [ ] 系统监控数据展示

### 第三优先级（P2）
- [ ] 威胁检测管理（规则配置、模型管理）
- [ ] 告警管理（规则配置、通知设置）

### 第四优先级（P3）
- [ ] 防御管理（IP封禁、防御策略）
- [ ] 系统管理（配置、备份、维护模式）

## 注意事项

1. 系统角色（admin, operator, user）不能被删除
2. 删除角色前需确保没有用户使用该角色
3. 密码重置功能需要相应权限
4. 日志默认保留90天，可配置清理
5. 所有操作都会记录到操作日志
