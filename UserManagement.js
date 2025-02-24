const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(false);
    const [modalVisible, setModalVisible] = useState(false);
    const [form] = Form.useForm();

    const columns = [
        {
            title: 'ID',
            dataIndex: 'id',
            key: 'id',
        },
        {
            title: '用户名',
            dataIndex: 'username',
            key: 'username',
        },
        {
            title: '创建时间',
            dataIndex: 'created_at',
            key: 'created_at',
            render: (text) => moment(text).format('YYYY-MM-DD HH:mm:ss')
        },
        {
            title: '操作',
            key: 'action',
            render: (_, record) => (
                <Space>
                    <Button 
                        type="link" 
                        onClick={() => showChangePasswordModal(record)}
                    >
                        修改密码
                    </Button>
                    {record.username !== 'admin' && (
                        <Button 
                            type="link" 
                            danger 
                            onClick={() => handleDelete(record.id)}
                        >
                            删除
                        </Button>
                    )}
                </Space>
            ),
        }
    ];

    const loadUsers = async () => {
        try {
            setLoading(true);
            const response = await fetch('http://localhost:5000/api/users', {
                credentials: 'include'
            });
            const data = await response.json();
            if (data.success) {
                setUsers(data.users);
            } else {
                message.error(data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            message.error('加载用户列表失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadUsers();
    }, []);

    const handleAddUser = async (values) => {
        try {
            const response = await fetch('http://localhost:5000/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(values),
                credentials: 'include'
            });
            const data = await response.json();
            if (data.success) {
                message.success('用户创建成功');
                setModalVisible(false);
                form.resetFields();
                loadUsers();
            } else {
                message.error(data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            message.error('创建用户失败');
        }
    };

    const handleDelete = async (userId) => {
        try {
            const response = await fetch(`http://localhost:5000/api/users/${userId}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            const data = await response.json();
            if (data.success) {
                message.success('用户删除成功');
                loadUsers();
            } else {
                message.error(data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            message.error('删除用户失败');
        }
    };

    return (
        <div className="site-layout-content">
            <div style={{ marginBottom: 16 }}>
                <Button 
                    type="primary" 
                    onClick={() => setModalVisible(true)}
                >
                    添加用户
                </Button>
            </div>

            <Table
                columns={columns}
                dataSource={users}
                rowKey="id"
                loading={loading}
            />

            <Modal
                title="添加用户"
                visible={modalVisible}
                onCancel={() => {
                    setModalVisible(false);
                    form.resetFields();
                }}
                footer={null}
            >
                <Form
                    form={form}
                    onFinish={handleAddUser}
                    layout="vertical"
                >
                    <Form.Item
                        name="username"
                        label="用户名"
                        rules={[{ required: true, message: '请输入用户名' }]}
                    >
                        <Input />
                    </Form.Item>
                    <Form.Item
                        name="password"
                        label="密码"
                        rules={[{ required: true, message: '请输入密码' }]}
                    >
                        <Input.Password />
                    </Form.Item>
                    <Form.Item>
                        <Button type="primary" htmlType="submit">
                            确定
                        </Button>
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
}; 